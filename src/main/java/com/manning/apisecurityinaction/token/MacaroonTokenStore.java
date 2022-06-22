package com.manning.apisecurityinaction.token;

import java.util.Optional;
import java.security.Key;

import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;
import spark.Request;

public class MacaroonTokenStore implements SecureTokenStore {
	private final TokenStore delegate;
	private final Key macKey;

	private MacaroonTokenStore(TokenStore delegate, Key macKey) {
		this.delegate = delegate;
		this.macKey = macKey;
	}

	// See chapter 6.4 for further detail regarding these factory methods for secure API design.
	public static SecureTokenStore wrap(ConfidentialTokenStore store, Key macKey) {
		return new MacaroonTokenStore(store, macKey);
	}

	public static AuthenticatedTokenStore wrap(TokenStore store, Key macKey) {
		return new MacaroonTokenStore(store, macKey);
	}

	@Override
	public String create(Request request, Token token) {
		// Delegate to another token store to create a unique identifier for macaroon.
		var identifier = delegate.create(request, token);
		// Build macaroon from an empty location hit, MAC key, and identifier.
		var macaroon = MacaroonsBuilder.create("", macKey.getEncoded(), identifier);

		return macaroon.serialize(); // Return serialized URL-safe string form of macaroon.
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		var macaroon = MacaroonsBuilder.deserialize(tokenId);
		var verifier = new MacaroonsVerifier(macaroon);
		verifier.satisfyGeneral(new TimestampCaveatVerifier());
		if (verifier.isValid(macKey.getEncoded())) {
			return delegate.read(request, macaroon.identifier);
		}
		return Optional.empty();
	}

	@Override
	public void revoke(Request request, String tokenId) {
		var macaroon = MacaroonsBuilder.deserialize(tokenId);
		delegate.revoke(request, macaroon.identifier);
	}
}
