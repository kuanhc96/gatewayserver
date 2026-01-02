package com.example.gatewayserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import feign.codec.Encoder;
import feign.form.spring.SpringFormEncoder;

@Configuration
public class AuthServerConfig {
    @Value("${authserver.location:http://localhost:9000}")
    private String authServerLocation;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(authServerLocation).build();
    }

    @Bean
    public Encoder feignFormEncoder() {
        return new SpringFormEncoder();
    }
}
