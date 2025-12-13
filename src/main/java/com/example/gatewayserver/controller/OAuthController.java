package com.example.gatewayserver.controller;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.RequiredArgsConstructor;

import com.example.gatewayserver.dto.AuthorizationState;
import com.example.gatewayserver.dto.SessionDTO;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequiredArgsConstructor
public class OAuthController {
	private static final ObjectMapper mapper = new ObjectMapper();

	private final CacheManager cacheManager;

	@PostMapping("/checkSession")
	public ResponseEntity<Boolean> checkSession(ServerHttpRequest request) {
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.add("Access-Control-Allow-Origin", "http://localhost:8080");
		responseHeaders.add("Access-Control-Allow-Credentials", "true");

		List<HttpCookie> cookiesList = request.getCookies().get("JSESSIONID");
		Cache.ValueWrapper wrapper = cacheManager.getCache("SESSION_CACHE").get(cookiesList.getFirst().getValue());
		if (wrapper == null) {
			return ResponseEntity.ok().headers(responseHeaders).body(false);
		}
		boolean hasSession = wrapper.get() != null;
		return ResponseEntity.ok().headers(responseHeaders).body(hasSession);
	}

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
			ServerHttpRequest request,
			ServerHttpResponse response,
			WebSession session,
            @RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
            @RequestParam(required = false) String error) throws IOException {
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<Boolean> isValidStateResponse = restTemplate.exchange(
				"http://localhost:9000/authState/verify",
				HttpMethod.POST,
				new HttpEntity<>(state),
				Boolean.class
		);

		if (!isValidStateResponse.getBody()) {
			throw new SecurityException("Invalid state parameter");
		}

		String[] parts = state.split("\\.");
		String payload = parts[0];
		byte[] jsonBytes = Base64.getUrlDecoder().decode(payload);
		AuthorizationState authState = mapper.readValue(jsonBytes, AuthorizationState.class);

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "authorization_code");
		body.add("code", code);
		body.add("state", state);
		body.add("redirect_uri", "http://localhost:8080/callback");
		body.add("client_id", "fe-client");
		body.add("client_secret", "secret1");

		HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(body, headers);
		ResponseEntity<Map> tokenResponse = restTemplate.exchange(
				"http://localhost:9000/oauth2/token",
				HttpMethod.POST,
				tokenRequest,
				Map.class
		);
		if (tokenResponse.getStatusCode() == HttpStatus.OK) {
			List<HttpCookie> cookiesList = request.getCookies().get("JSESSIONID");
			SessionDTO sessionDTO = SessionDTO.builder()
					.sessionId(cookiesList.getFirst().getValue())
					.token(tokenResponse.getBody().get("access_token").toString())
					.build();
			cacheManager.getCache("SESSION_CACHE").put(cookiesList.getFirst().getValue(), sessionDTO);

			if (authState.rememberMe()) {
				String cookieId = UUID.randomUUID().toString();
				SessionDTO rememberMeSession = SessionDTO.builder()
						.sessionId(cookieId)
						.token(tokenResponse.getBody().get("refresh_token").toString())
						.build();
				cacheManager.getCache("SESSION_CACHE").put(cookieId, rememberMeSession);

				ResponseCookie rememberMeCookie = ResponseCookie.from("RMC", cookieId)
						.maxAge(Duration.ofHours(8))
						.domain(null)
						.path("/")
						.httpOnly(true)
						.secure(true)
						.sameSite("Strict")
						.partitioned(false)
						.build();
				response.addCookie(rememberMeCookie);

			}

			HttpHeaders responseHeaders = new HttpHeaders();
			responseHeaders.add("Access-Control-Allow-Origin", "http://localhost:8080");
			responseHeaders.add("Access-Control-Allow-Credentials", "true");
			return ResponseEntity.ok().headers(responseHeaders).body(Map.of("successUrl", authState.successUrl()));
		} else {
			return ResponseEntity.status(tokenResponse.getStatusCode()).body("Failed to retrieve access token");
		}
	}
}
