package com.manning.apisecurityinaction.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import org.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.Filter;
import static spark.Spark.halt;
import com.manning.apisecurityinaction.token.TokenStore;
import com.manning.apisecurityinaction.token.SecureTokenStore;

public class TokenController {
	private static final String DEFAULT_SCOPES =
		"create_space post_message read_message list_messages delete_message add_member";
	private final SecureTokenStore tokenStore;

	public TokenController(SecureTokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	public Filter requireScope(String method, String requiredScope) {
		return (request, response) -> {
			if (!method.equalsIgnoreCase(request.requestMethod())) {
				return; // Ignore filter if HTTP method doesn't match request.
			}
			// If token is unscoped (then user directly authenticated the request with Basic authentication).
			// Any client with access to user password could issue themselves a token with any scope.
			// So we skip the scope check filter and allow the request to proceed.
			var tokenScope = request.<String>attribute("scope");
			if (tokenScope == null) return;
			// See Bearer authentication scheme for further detail regarding dedicated error code.
			// Also, see chapter 7.1.1.
			if (!Set.of(tokenScope.split(" ")).contains(requiredScope)) {
				response.header("WWW-Authenticate",
					"Bearer error=\"insufficient_scope\",scope=\"" + requiredScope + "\"");
				halt(403);
			}
		};
	}

	public void validateToken(Request request, Response response) {
		// Parse Bearer token from Authorization header, see chapter 5.2.2.
		var tokenId = request.headers("Authorization");
		if (tokenId == null || !tokenId.startsWith("Bearer ")) {
			return; // Allows HTTP Basic authn to still work at login endpoint.
		}
		tokenId = tokenId.substring(7);

		tokenStore.read(request, tokenId).ifPresent(token -> {
			if (Instant.now().isBefore(token.expiry)) {
				request.attribute("subject", token.username);
				token.attributes.forEach(request::attribute);
			}
			else {
				response.header("WWW-Authenticate", 
					"Bearer error=\"invalid_token\",error_description=\"Expired\"");
				halt(401);
			}
		});
	}

	public JSONObject login(Request request, Response response) {
		String subject = request.attribute("subject");
		// See https://mkyong.com/java/java-how-to-get-current-date-time-date-and-calender/.
		var expiry = Instant.now().plus(8, ChronoUnit.MINUTES);

		var token = new TokenStore.Token(expiry, subject);
		var scope = request.queryParamOrDefault("scope", DEFAULT_SCOPES);
		token.attributes.put("scope", scope);
		var tokenId = tokenStore.create(request, token);

		response.status(201);
		return new JSONObject().put("token", tokenId);
	}

	public JSONObject logout(Request request, Response response) {
		// See code comments for validateToken().
		var tokenId = request.headers("Authorization");
		if (tokenId == null || !tokenId.startsWith("Bearer ")) {
			throw new IllegalArgumentException("missing token header");
		}
		tokenId = tokenId.substring(7);

		tokenStore.revoke(request, tokenId);

		response.status(200);
		return new JSONObject();
	}
}
