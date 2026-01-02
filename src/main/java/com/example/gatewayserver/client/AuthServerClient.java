package com.example.gatewayserver.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.gatewayserver.config.AuthServerConfig;
import com.example.gatewayserver.dto.TokenResponse;

@FeignClient(name = "freelance-authserver", configuration = AuthServerConfig.class)
public interface AuthServerClient {
    @PostMapping(value = "/authState/verify", consumes = MediaType.TEXT_PLAIN_VALUE)
    Boolean isValidState(@RequestBody String state);

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse getToken(
        @RequestParam("grant_type") String grantType,
        @RequestParam("code") String code,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestParam("client_id") String clientId,
        @RequestParam("client_secret") String clientSecret,
        @RequestParam("state") String state
    );
}
