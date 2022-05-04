package com.manning.apisecurityinaction.token;

import javax.crypto.SecretKey;
import java.util.Optional;
import java.util.Date;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import spark.Request;

public class SignedJwtTokenStore implements TokenStore {
	private final JWSSigner signer;
	private final JWSVerifier verifier;
	private final JWSAlgorithm algorithm;
	private final String audience;

	public SignedJwtTokenStore(JWSSigner signer, JWSVerifier verifier, JWSAlgorithm algorithm, String audience) {
		this.signer = signer;
		this.verifier = verifier;
		this.algorithm = algorithm;
		this.audience = audience;
	}

	@Override
	public String create(Request request, Token token) {
		var claimsSet = new JWTClaimsSet.Builder()
			.subject(token.username)
			.audience(audience)
			.expirationTime(Date.from(token.expiry))
			.claim("attrs", token.attributes)
			.build();

		var header = new JWSHeader(JWSAlgorithm.HS256);
		var jwt = new SignedJWT(header, claimsSet);
		try {
			jwt.sign(signer);
			return jwt.serialize();
		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		// TODO
		return Optional.empty();
	}

	@Override
	public void revoke(Request request, String tokenId) {
		// TODO
	}
}
