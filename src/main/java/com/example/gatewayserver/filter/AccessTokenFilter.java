package com.example.gatewayserver.filter;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;
import redis.clients.jedis.RedisClient;

@Order(1)
@Component
@RequiredArgsConstructor
public class AccessTokenFilter implements GlobalFilter {

    private final RedisClient redisClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        List<HttpCookie> jsessionCookiesList = exchange.getRequest().getCookies().get("JSESSIONID");
        ServerWebExchange mutatedExchange = exchange;
        if (jsessionCookiesList != null && !jsessionCookiesList.isEmpty()) {
            String jsessionId = jsessionCookiesList.get(0).getValue();
            String accessToken = redisClient.get(generateAccessTokenKey(jsessionId));
            mutatedExchange = exchange.mutate().request(exchange.getRequest().mutate()
                    .header("Authorization", "Bearer " + accessToken)
                    .build()).build();
        }

        return chain.filter(mutatedExchange);
    }

    private String generateAccessTokenKey(String id) {
        return "access_token#" + id;
    }

}
