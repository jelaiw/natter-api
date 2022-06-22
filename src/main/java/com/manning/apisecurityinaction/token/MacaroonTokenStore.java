package com.manning.apisecurityinaction.token;

import java.util.Optional;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
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
		verifier.satisfyExact("method = " + request.requestMethod());
		verifier.satisfyGeneral(new SinceVerifier(request));
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

	private static class SinceVerifier implements GeneralCaveatVerifier {
		private final Request request;

		private SinceVerifier(Request request) {
			this.request = request;
		}

		@Override
		public boolean verifyCaveat(String caveat) {
			if (caveat.startsWith("since > ")) {
				// Parse restriction if caveat matches.
				var minSince = Instant.parse(caveat.substring(8));

				// Determine "since" parameter value on the request.
				var reqSince = Instant.now().minus(1, ChronoUnit.DAYS);
				if (request.queryParams("since") != null) {
					reqSince = Instant.parse(request.queryParams("since"));
				}
				// Satisfy caveat if the request is after the earliest message restriction.
				return reqSince.isAfter(minSince);
			}
			// Reject all other caveats.
			return false;
		}
	}
}
