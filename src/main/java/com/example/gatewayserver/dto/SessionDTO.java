package com.example.gatewayserver.dto;

import lombok.Builder;

@Builder
public record SessionDTO (String sessionId, String token) {
}
