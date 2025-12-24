package com.example.gatewayserver.controller;

import java.net.URI;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LoginController {
    @GetMapping("/login")
    public void authorize(ServerHttpResponse response) {
        URI uri = UriComponentsBuilder.fromUriString("http://localhost:9000/login").build().toUri();
		response.getHeaders().setLocation(uri);
		response.getHeaders().setAccessControlAllowOrigin("http://localhost:8080");
		response.setStatusCode(HttpStatus.FOUND);
    }
}
