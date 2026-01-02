package com.example.gatewayserver.controller;

import java.io.IOException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebSession;

import com.example.gatewayserver.client.AuthServerClient;
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

	@Value("${rememberme.expiration-hours:8}")
	private Integer rememberMeExpirationHours;

	private static final ObjectMapper mapper = new ObjectMapper();

	private final JwtDecoder jwtDecoder;
	private final RedisClient redisClient;
	private final AuthServerClient authServerClient;

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
			SessionResponse emptySession = SessionResponse.builder().email("").role("").userGUID("").build();
            return ResponseEntity.ok().headers(responseHeaders).body(emptySession);
        }

		Jwt jwt = jwtDecoder.decode(idToken);

		Map<String, String> claims = jwt.getClaims().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
		SessionResponse sessionResponse = SessionResponse.builder()
				.userGUID(claims.get("userGUID"))
				.email(claims.get("sub"))
				.role(claims.get("role"))
				.build();
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

		TokenResponse tokenResponse = sendTokenRequest(code, state);

		if (tokenResponse != null) {
            String accessToken = tokenResponse.access_token();
            String refreshToken = tokenResponse.refresh_token();
            String idToken = tokenResponse.id_token();
			Integer expiresIn = tokenResponse.expires_in();

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
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to retrieve access token");
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
		boolean isValidStateResponse = authServerClient.isValidState(state);

		if (!isValidStateResponse) {
			throw new SecurityException("Invalid state parameter");
		}
	}

	private AuthorizationState parseState(String state) throws IOException {
		String[] parts = state.split("\\.");
		String payload = parts[0];
		byte[] jsonBytes = Base64.getUrlDecoder().decode(payload);
		return mapper.readValue(jsonBytes, AuthorizationState.class);
	}

	private TokenResponse sendTokenRequest(String code, String state) {
		return authServerClient.getToken(
				"authorization_code",
				code,
				clientLocation + "/callback",
				"fe-client",
				"secret1",
				state
		);
	}
}
