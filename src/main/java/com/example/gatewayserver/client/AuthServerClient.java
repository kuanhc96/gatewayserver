package com.example.gatewayserver.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.gatewayserver.config.AuthServerConfig;
import com.example.gatewayserver.dto.GetAccessTokenRequest;
import com.example.gatewayserver.dto.TokenResponse;

@FeignClient(name = "freelance-authserver", configuration = AuthServerConfig.class)
public interface AuthServerClient {
    @PostMapping(value = "/oauth2/token", consumes = "application/x-www-form-urlencoded")
    TokenResponse getToken(GetAccessTokenRequest tokenRequest);

    @PostMapping(value = "/api/verify/state", consumes = "application/json")
    Boolean verifyAuthorizationState(String state);
}
