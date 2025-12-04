package com.example.gatewayserver.controller;

import java.net.URI;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class OAuthController {
	@GetMapping("/authorize")
	public void authorize(ServerHttpResponse response) {
		URI uri = UriComponentsBuilder.fromUriString("http://localhost:9000/oauth2/authorize")
				.queryParam("client_id", "fe-client")
				.queryParam("redirect_uri", "http://localhost:8080/callback")
				.queryParam("response_type", "code")
				.queryParam("scope", "openid")
				.queryParam("state", "abcde")
				.build().toUri();

		response.getHeaders().setLocation(uri);
		response.getHeaders().setAccessControlAllowOrigin("http://localhost:8080");
		response.setStatusCode(HttpStatus.FOUND);
	}

	@PostMapping("/callback")
	public ResponseEntity<?> callback(
            @RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
            @RequestParam(required = false) String error) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "authorization_code");
		body.add("code", code);
		body.add("state", state);
		body.add("redirect_uri", "http://localhost:8080/callback");
		body.add("client_id", "fe-client");
		body.add("client_secret", "secret1");

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
		ResponseEntity<Map> tokenResponse = restTemplate.exchange(
				"http://localhost:9000/oauth2/token",
				HttpMethod.POST,
				request,
				Map.class
		);
		if (tokenResponse.getStatusCode() == HttpStatus.OK) {
			HttpHeaders responseHeaders = new HttpHeaders();
			responseHeaders.add("Access-Control-Allow-Origin", "*");
			return ResponseEntity.ok().headers(responseHeaders).body(tokenResponse.getBody());
		} else {
			return ResponseEntity.status(tokenResponse.getStatusCode()).body("Failed to retrieve access token");
		}
	}
}
