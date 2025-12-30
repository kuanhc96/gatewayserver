package com.example.gatewayserver.dto;

import lombok.Builder;

@Builder
public record SessionResponse(String userGUID, String email, String role) {
}
