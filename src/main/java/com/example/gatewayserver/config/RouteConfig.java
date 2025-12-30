package com.example.gatewayserver.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;
import redis.clients.jedis.RedisClient;

@Configuration
@RequiredArgsConstructor
public class RouteConfig {
    private final RedisClient redisClient;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

//    @Bean
//    public RouteLocator routeConfig(RouteLocatorBuilder routeLocatorBuilder) {
//
//        return routeLocatorBuilder.routes()
//                .route(p -> p
//                        .path("*")
//                        .filters(
//                                f -> f.addRequestHeader("Authorization", )
//                        )
//                )
//    }
}
