package com.manning.apisecurityinaction.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.json.JSONObject;
import spark.Request;
import spark.Response;
import com.manning.apisecurityinaction.token.TokenStore;

public class TokenController {
	private final TokenStore tokenStore;

	public TokenController(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	public void validateToken(Request request, Response response) { // From Listing 4.9.
		tokenStore.read(request, null).ifPresent(token -> {
			if (Instant.now().isBefore(token.expiry)) {
				request.attribute("subject", token.username);
				token.attributes.forEach(request::attribute);
			}
		});
	}

	public JSONObject login(Request request, Response response) {
		String subject = request.attribute("subject");
		// See https://mkyong.com/java/java-how-to-get-current-date-time-date-and-calender/.
		var expiry = Instant.now().plus(8, ChronoUnit.MINUTES);

		var token = new TokenStore.Token(expiry, subject);
		var tokenId = tokenStore.create(request, token);

		response.status(201);
		return new JSONObject().put("token", tokenId);
	}
}
