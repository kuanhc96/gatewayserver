package com.example.gatewayserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import redis.clients.jedis.RedisClient;

@Configuration
@RequiredArgsConstructor
public class RouteConfig {
    private final RedisClient redisClient;

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
