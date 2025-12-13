package com.example.gatewayserver.dto;

public record AuthorizationState(boolean rememberMe, String successUrl) {
}
