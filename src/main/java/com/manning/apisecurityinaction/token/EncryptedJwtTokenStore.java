package com.manning.apisecurityinaction.token;

import java.util.Optional;
import java.util.Date;
import java.util.Set;
import javax.crypto.SecretKey;
import java.text.ParseException;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import spark.Request;

public class EncryptedJwtTokenStore implements SecureTokenStore {
	private final SecretKey encKey;
	private final DatabaseTokenStore tokenAllowList;

	public EncryptedJwtTokenStore(SecretKey encKey, DatabaseTokenStore tokenAllowList) {
		this.encKey = encKey;
		this.tokenAllowList = tokenAllowList;
	}

	@Override
	public String create(Request request, Token token) {
		// Clever re-use of DatabaseTokenStore for hybrid tokens desribed in chapter 6.5.1.
		var allowListToken = new Token(token.expiry, token.username);
		var jwtId = tokenAllowList.create(request, allowListToken);

		var claimsBuilder = new JWTClaimsSet.Builder()
			.jwtID(jwtId) // jti claim.
			.subject(token.username)
			.audience("https://localhost:4567")
			.expirationTime(Date.from(token.expiry));
		token.attributes.forEach(claimsBuilder::claim);
			
		var header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
		var jwt = new EncryptedJWT(header, claimsBuilder.build());

		try {
			var encrypter = new DirectEncrypter(encKey);
			jwt.encrypt(encrypter);

		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}

		return jwt.serialize();
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		try {
			var jwt = EncryptedJWT.parse(tokenId);

			var decrypter = new DirectDecrypter(encKey);
			jwt.decrypt(decrypter);

			var claims = jwt.getJWTClaimsSet();
			// Check if allowlist token has been revoked.
			var jwtId = claims.getJWTID();
			if (tokenAllowList.read(request, jwtId).isEmpty()) {
				return Optional.empty();
			}
			// Validate other claims.
			if (!claims.getAudience().contains("https://localhost:4567")) {
				return Optional.empty();
			}
			var expiry = claims.getExpirationTime().toInstant();
			var subject = claims.getSubject();
			var token = new Token(expiry, subject);
			var ignore = Set.of("exp", "sub", "aud");
			for (var attr : claims.getClaims().keySet()) {
				if (ignore.contains(attr)) continue;
				token.attributes.put(attr, claims.getStringClaim(attr));
			}

			return Optional.of(token);
		}
		catch (ParseException | JOSEException e) {
			return Optional.empty();
		}
	}

	@Override
	public void revoke(Request request, String tokenId) {
		try {
			// Parse, decrypt, and validate JWT the usual way.
			var jwt = EncryptedJWT.parse(tokenId);
			var decrypter = new DirectDecrypter(encKey);
			jwt.decrypt(decrypter);
			var claims = jwt.getJWTClaimsSet();
			// Revoke JWT ID from database (allow list).
			tokenAllowList.revoke(request, claims.getJWTID());
		}
		catch (ParseException | JOSEException e) {
			throw new IllegalArgumentException("invalid token", e);
		}
	}
}
