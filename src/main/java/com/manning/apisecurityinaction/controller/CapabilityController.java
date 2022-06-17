package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.TokenStore.Token;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import static java.time.Instant.now;
import java.time.Duration;
import java.net.URI;
import java.util.Objects;

import spark.Request;
import spark.Response;

public class CapabilityController {
	private final SecureTokenStore tokenStore;

	public CapabilityController(SecureTokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	public URI createUri(Request request, String path, String perms, Duration expiryDuration) {
		// Associate capability token with an authenticated user to harden capabilities.
		var subject = (String) request.attribute("subject");
		var token = new Token(now().plus(expiryDuration), subject);
		token.attributes.put("path", path);
		token.attributes.put("perms", perms);

		var tokenId = tokenStore.create(request, token);

		var uri = URI.create(request.uri());
		// Add token to URI as a query parameter, per RFC 6750.
		return uri.resolve(path + "?access_token=" + tokenId);
	}

	public void lookupPermissions(Request request, Response response) {
		var tokenId = request.queryParams("access_token");
		if (tokenId == null) { 
			return;
		}

		tokenStore.read(request, tokenId).ifPresent(token -> {
			// Ensure capability can't be used without a matching user session.
			if (!Objects.equals(token.username, request.attribute("subject"))) {
				return;
			}

			var tokenPath = token.attributes.get("path");
			if (Objects.equals(tokenPath, request.pathInfo())) {
				request.attribute("perms", token.attributes.get("perms"));
			}
		});
	}
}
