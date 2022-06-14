package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.TokenStore.Token;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import static java.time.Instant.now;
import java.time.Duration;
import java.net.URI;

import spark.Request;
import spark.Response;

public class CapabilityController {
	private final SecureTokenStore tokenStore;

	public CapabilityController(SecureTokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	public URI createUri(Request request, String path, String perms, Duration expiryDuration) {
		// Set username field to null because capabilities are not tied to an individual user account.
		var token = new Token(now().plus(expiryDuration), null);
		token.attributes.put("path", path);
		token.attributes.put("perms", perms);
		var tokenId = tokenStore.create(request, token);
		var uri = URI.create(request.uri());
		// Add token to URI as a query parameter, per RFC 6750.
		return uri.resolve(path + "?access_token=" + tokenId);
	}
}
