package com.example.gatewayserver.dto;

import lombok.Builder;

@Builder
public record SessionResponse(String email, String role) {
}
