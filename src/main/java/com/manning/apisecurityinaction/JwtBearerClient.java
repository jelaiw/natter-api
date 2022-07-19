package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;

import com.nimbusds.jose.jwk.JWKSet;
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
	}
}
