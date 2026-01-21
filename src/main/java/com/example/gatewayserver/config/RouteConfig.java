package com.example.gatewayserver.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import redis.clients.jedis.RedisClient;

@Configuration
@RequiredArgsConstructor
public class RouteConfig {
    private final RedisClient redisClient;

    @Bean
    public RouteLocator routeFilterConfig(RouteLocatorBuilder routeLocatorBuilder) {

        return routeLocatorBuilder.routes()
                .route(p -> p
                        .path("/freelance/**")
                        .filters(
                    f -> f.rewritePath("/freelance/(?<segment>.*)", "/api/${segment}")
                        )
                        .uri("lb://FREELANCE-RESOURCE-BACKEND")
                ).build();
    }
}
