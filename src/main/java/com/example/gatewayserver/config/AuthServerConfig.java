package com.example.gatewayserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
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
    public RestTemplate authServerClient() {
        return new RestTemplate();
    }

    @Bean
    public HttpMessageConverters messageConverters(ObjectMapper objectMapper) {
        return new HttpMessageConverters(new MappingJackson2HttpMessageConverter(objectMapper));
    }

    @Bean
    public Encoder feignFormEncoder() {
        return new SpringFormEncoder();
    }
}
