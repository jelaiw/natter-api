package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.UUID;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.ECDSASigner;
import static spark.Spark.secure;
import static spark.Spark.get;

public class JwtBearerClient {
	public static void main(String... args) throws Exception {
		var password = "changeit".toCharArray();
		var keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream("keystore.p12"), password);
		var privateKey = (ECPrivateKey) keyStore.getKey("es256-key", password);

		// Load JWK set from keystore. Make sure it contains only public keys!
		var jwkSet = JWKSet.load(keyStore, alias -> password).toPublicJWKSet();

		// Publish JWK set to an HTTPS endpoint.
		secure("localhost.p12", "changeit", null, null);
		get("/jwks", (request, response) -> {
			response.type("application/jwk-set+json");
			return jwkSet.toString();
		});

		// See chapter 11.3.2 for further context.
		var clientId = "test";
		var as = "https://as.example.com:8080/oauth2/access_token";
		var header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("es256-key").build();
		var claims = new JWTClaimsSet.Builder()
				.subject(clientId)
				.issuer(clientId)
				.expirationTime(Date.from(now().plus(30, SECONDS)))
				.audience(as)
				.jwtID(UUID.randomUUID().toString()) // Add a random JWT ID claim to prevent replay.
				.build();
		var jwt = new SignedJWT(header, claims);
		jwt.sign(new ECDSASigner(privateKey)); // Sign JWT with private key.
		var assertion = jwt.serialize();
	}
}
