package com.example.gatewayserver.controller;

import java.io.IOException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
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

import com.example.gatewayserver.dto.SessionResponse;
import com.example.gatewayserver.dto.TokenResponse;
import lombok.RequiredArgsConstructor;

import com.example.gatewayserver.dto.AuthorizationState;
import com.fasterxml.jackson.databind.ObjectMapper;
import redis.clients.jedis.RedisClient;
import redis.clients.jedis.params.SetParams;

@RestController
@RequiredArgsConstructor
public class OAuthController {
	@Value("${client.location}")
	private String clientLocation;

	@Value("${authserver.location}")
	private String authserverLocation;

	@Value("${rememberme.expiration-hours:8}")
	private Integer rememberMeExpirationHours;

	private static final ObjectMapper mapper = new ObjectMapper();

	private final JwtDecoder jwtDecoder;
	private final RedisClient redisClient;
	private final RestTemplate restTemplate;

    @GetMapping("/checkSession")
    public ResponseEntity<SessionResponse> getOpenIdSession(ServerHttpRequest request) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", clientLocation);
        responseHeaders.add("Access-Control-Allow-Credentials", "true");

		List<HttpCookie> rmcCookiesList = request.getCookies().get("RMC");
		String idToken;
		if (!ObjectUtils.isEmpty(rmcCookiesList)) {
			idToken = redisClient.get(generateOpenIdTokenKey(rmcCookiesList.getFirst().getValue()));
		} else {
			List<HttpCookie> jsessionCookiesList = request.getCookies().get("JSESSIONID");
			idToken = redisClient.get(generateOpenIdTokenKey(jsessionCookiesList.getFirst().getValue()));
		}
        if (idToken == null) {
            return ResponseEntity.ok().headers(responseHeaders).body(null);
        }

		Jwt jwt = jwtDecoder.decode(idToken);

		Map<String, String> claims = jwt.getClaims().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
		SessionResponse sessionResponse = SessionResponse.builder().email(claims.get("sub")).role(claims.get("role")).build();
		return ResponseEntity.ok().headers(responseHeaders).body(sessionResponse);
    }

	@PostMapping("/callback")
	public ResponseEntity<?> callback(
			ServerHttpRequest request,
			ServerHttpResponse response,
			WebSession session,
            @RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
            @RequestParam(required = false) String error) throws IOException {

		verifyState(state);
		AuthorizationState authState = parseState(state);

		ResponseEntity<TokenResponse> tokenResponse = sendTokenRequest(code, state);

		if (tokenResponse.getStatusCode() == HttpStatus.OK && tokenResponse.getBody() != null) {
            String accessToken = tokenResponse.getBody().access_token();
            String refreshToken = tokenResponse.getBody().refresh_token();
            String idToken = tokenResponse.getBody().id_token();
			Integer expiresIn = tokenResponse.getBody().expires_in();

			String jSessionId = request.getCookies().get("JSESSIONID").getFirst().getValue();

			redisClient.set(generateAccessTokenKey(jSessionId), accessToken, SetParams.setParams().nx().ex(expiresIn));

			if (authState.rememberMe()) {
				Long rememberMeExpirationSeconds = rememberMeExpirationHours * 3600L;
				String rememberMeCookieId = UUID.randomUUID().toString();
				redisClient.set(generateRefreshTokenKey(rememberMeCookieId), refreshToken, SetParams.setParams().nx().ex(rememberMeExpirationSeconds));

				ResponseCookie rememberMeCookie = ResponseCookie.from("RMC", rememberMeCookieId)
						.maxAge(Duration.ofHours(rememberMeExpirationHours))
						.domain(null)
						.path("/")
						.httpOnly(true)
						.secure(true)
						.sameSite("Strict")
						.partitioned(false)
						.build();
				response.addCookie(rememberMeCookie);

                redisClient.set(generateOpenIdTokenKey(rememberMeCookieId), idToken, SetParams.setParams().nx().ex(rememberMeExpirationSeconds));
			} else {
                redisClient.set(generateOpenIdTokenKey(jSessionId), idToken, SetParams.setParams().nx().ex(expiresIn));
            }

			HttpHeaders responseHeaders = new HttpHeaders();
			responseHeaders.add("Access-Control-Allow-Origin", clientLocation);
			responseHeaders.add("Access-Control-Allow-Credentials", "true");
			return ResponseEntity.ok().headers(responseHeaders).body(Map.of("successUrl", authState.successUrl()));
		} else {
			return ResponseEntity.status(tokenResponse.getStatusCode()).body("Failed to retrieve access token");
		}
	}

	private String generateAccessTokenKey(String id) {
		return "access_token#" + id;
	}

	private String generateRefreshTokenKey(String id) {
		return "refresh_token#" + id;
	}

	private String generateOpenIdTokenKey(String id) {
		return "openid_token#" + id;
	}

	private void verifyState(String state) {
		ResponseEntity<Boolean> isValidStateResponse = restTemplate.exchange(
				authserverLocation + "/authState/verify",
				HttpMethod.POST,
				new HttpEntity<>(state),
				Boolean.class
		);

		if (!isValidStateResponse.getBody()) {
			throw new SecurityException("Invalid state parameter");
		}
	}

	private AuthorizationState parseState(String state) throws IOException {
		String[] parts = state.split("\\.");
		String payload = parts[0];
		byte[] jsonBytes = Base64.getUrlDecoder().decode(payload);
		return mapper.readValue(jsonBytes, AuthorizationState.class);
	}

	private ResponseEntity<TokenResponse> sendTokenRequest(String code, String state) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "authorization_code");
		body.add("code", code);
		body.add("state", state);
		body.add("redirect_uri", clientLocation + "/callback"); // is this needed in the token API request?
		body.add("client_id", "fe-client");
		body.add("client_secret", "secret1");

		HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(body, headers);
		return restTemplate.exchange(
				authserverLocation + "/oauth2/token",
				HttpMethod.POST,
				tokenRequest,
				TokenResponse.class
		);

	}
}
