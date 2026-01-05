package com.example.gatewayserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AuthServerConfig {
    @Value("${authserver.location:http://localhost:9000}")
    private String authServerLocation;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(authServerLocation).build();
    }

    @Bean
    public RestTemplate authServerClient() {
        return new RestTemplate();
    }
}
