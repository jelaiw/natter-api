package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.TokenStore.Token;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import static java.time.Instant.now;
import java.time.Duration;
import java.net.URI;
import java.util.Objects;

import spark.Request;
import spark.Response;
import static spark.Spark.halt;
import org.json.JSONObject;

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

	public JSONObject share(Request request, Response response) {
		var json = new JSONObject(request.body());

		// Parse original capability URI for token.
		var capUri = URI.create(json.getString("uri"));
		var path = capUri.getPath();
		var query = capUri.getQuery();
		var tokenId = query.substring(query.indexOf('=') + 1);

		// Look up token and check that the resource path matches.
		var token = tokenStore.read(request, tokenId).orElseThrow();
		if (!Objects.equals(token.attributes.get("path"), path)) {
			throw new IllegalArgumentException("incorrect path");
		}

		// Check that requested permissions are a subset of the token perms.
		var tokenPerms = token.attributes.get("perms");
		var perms = json.optString("perms", tokenPerms);
		if (!tokenPerms.contains(perms)) {
			halt(403);
		}

		// Create and store new capability token (for intended user).
		var user = json.getString("user");
		var newToken = new Token(token.expiry, user);
		newToken.attributes.put("path", path);
		newToken.attributes.put("perms", perms);
		var newTokenId = tokenStore.create(request, newToken);

		// Return requested capability URI.
		var uri = URI.create(request.uri());
		var newCapUri = uri.resolve(path + "?access_token=" + newTokenId);
		return new JSONObject().put("uri", newCapUri);
	}
}
