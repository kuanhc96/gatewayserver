package com.example.gatewayserver.controller;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.core.ParameterizedTypeReference;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
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
	private final JwtDecoder jwtDecoder;

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

    @GetMapping("/openIdSession")
    public ResponseEntity<Map<String, String>> getOpenIdSession(ServerHttpRequest request) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", "http://localhost:8080");
        responseHeaders.add("Access-Control-Allow-Credentials", "true");

		List<HttpCookie> rmcCookiesList = request.getCookies().get("RMC");
		String openIdSessionId;
		if (!ObjectUtils.isEmpty(rmcCookiesList)) {
			openIdSessionId = rmcCookiesList.getFirst().getValue() + "_OPENID";
		} else {
			List<HttpCookie> jsessionCookiesList = request.getCookies().get("JSESSIONID");
			openIdSessionId = jsessionCookiesList.getFirst().getValue() + "_OPENID";
		}
        Cache.ValueWrapper wrapper = cacheManager.getCache("SESSION_CACHE").get(openIdSessionId);
        if (wrapper == null || wrapper.get() == null) {
            return ResponseEntity.ok().headers(responseHeaders).body(new HashMap<>());
        }
        SessionDTO openIdSession = (SessionDTO) wrapper.get();
		if (openIdSession == null) {
			return ResponseEntity.ok().headers(responseHeaders).body(new HashMap<>());
		}

		Jwt jwt = jwtDecoder.decode(openIdSession.token());

		Map<String, String> claims = jwt.getClaims().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
		return ResponseEntity.ok().headers(responseHeaders).body(claims);
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
		if (tokenResponse.getStatusCode() == HttpStatus.OK && tokenResponse.getBody() != null) {
            String accessToken = tokenResponse.getBody().get("access_token").toString();
            String refreshToken = tokenResponse.getBody().get("refresh_token").toString();
            String idToken = tokenResponse.getBody().get("id_token").toString();

			List<HttpCookie> cookiesList = request.getCookies().get("JSESSIONID");

            String jSessionID = cookiesList.getFirst().getValue();
			SessionDTO sessionDTO = SessionDTO.builder()
					.sessionId(jSessionID)
					.token(accessToken)
					.build();
			cacheManager.getCache("SESSION_CACHE").put(jSessionID, sessionDTO);

            String openIdSessionId;
			if (authState.rememberMe()) {
				String rememberMeCookieId = UUID.randomUUID().toString();
				SessionDTO rememberMeSession = SessionDTO.builder()
						.sessionId(rememberMeCookieId)
						.token(refreshToken)
						.build();
				cacheManager.getCache("SESSION_CACHE").put(rememberMeCookieId, rememberMeSession);

				ResponseCookie rememberMeCookie = ResponseCookie.from("RMC", rememberMeCookieId)
						.maxAge(Duration.ofHours(8))
						.domain(null)
						.path("/")
						.httpOnly(true)
						.secure(true)
						.sameSite("Strict")
						.partitioned(false)
						.build();
				response.addCookie(rememberMeCookie);

                openIdSessionId = rememberMeCookieId + "_OPENID";
                SessionDTO openIdSession = SessionDTO.builder()
                        .sessionId(openIdSessionId)
                        .token(idToken)
                        .build();
                cacheManager.getCache("SESSION_CACHE").put(openIdSessionId, openIdSession);
			} else {
                openIdSessionId = jSessionID + "_OPENID";
                SessionDTO openIdSession = SessionDTO.builder()
                        .sessionId(openIdSessionId)
                        .token(idToken)
                        .build();
                cacheManager.getCache("SESSION_CACHE").put(openIdSessionId, openIdSession);
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
