package com.manning.apisecurityinaction.token;

import java.util.Optional;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import spark.Request;

public class CookieTokenStore implements SecureTokenStore {
	@Override
	public String create(Request request, Token token) {
		// WARNING: Vulnerable to session fixation attack.
//		var session = request.session(true);

		// Avoid session fixation attack.
		// See chapter 4.3.1 for further detail.
		var session = request.session(false);
		if (session != null) {
			session.invalidate();
		}
		session = request.session(true);

		session.attribute("username", token.username);
		session.attribute("expiry", token.expiry);
		session.attribute("attrs", token.attributes);

		// URL-safe Base64 encode of SHA-256 hash.
		// See chapter 4.4.3 for further detail.
		return Base64url.encode(sha256(session.id())); 
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		var session = request.session(false);
		if (session == null) {
			return Optional.empty();
		}

		var provided = Base64url.decode(tokenId);
		var computed = sha256(session.id());

		// Note, MessageDigest.isEquals() implements a constant-time equality comparison.
		// Read more about avoiding timing attacks in chapter 4.4.3.
		if (!MessageDigest.isEqual(computed, provided)) {
			return Optional.empty();
		}

		var token = new Token(session.attribute("expiry"), session.attribute("username"));
		token.attributes.putAll(session.attribute("attrs"));

		return Optional.of(token);
	}

	static byte[] sha256(String tokenId) {
		try {
			var sha256 = MessageDigest.getInstance("SHA-256");
			return sha256.digest(tokenId.getBytes(StandardCharsets.UTF_8));
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public void revoke(Request request, String tokenId) {
		var session = request.session(false);
		if (session == null) return;

		var provided = Base64url.decode(tokenId);
		var computed = sha256(session.id());

		// See MessageDigest.isEquals() note in read() implementation.
		if (!MessageDigest.isEqual(computed, provided)) {
			return;
		}

		session.invalidate();
	}
}
