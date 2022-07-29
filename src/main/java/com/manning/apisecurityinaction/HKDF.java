package com.manning.apisecurityinaction;

import java.security.Key;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import static java.util.Objects.checkIndex;
import static java.nio.charset.StandardCharsets.UTF_8;

public class HKDF {
	public static Key expand(Key masterKey, String context, int outputKeySize, String algorithm) throws GeneralSecurityException {
		// Make sure caller isn't asking for too much key material.
		checkIndex(outputKeySize, 255*32);

		// Initialize MAC with master key.
		var hmac = Mac.getInstance("HmacSHA256");
		hmac.init(masterKey);

		var output = new byte[outputKeySize];
		var block = new byte[0];
		for (int i = 0; i < outputKeySize; i+= 32) { // Loop until requested output size has been generated.
			hmac.update(block); // Include output block of the last loop in new HMAC.
			hmac.update(context.getBytes(UTF_8)); // Include context string.
			hmac.update((byte) ((i / 32) + 1)); // Include block counter.
			block = hmac.doFinal(); // Copy new HMAC tag to next block of output.
			System.arraycopy(block, 0, output, i, Math.min(outputKeySize - i, 32));
		}

		return new SecretKeySpec(output, algorithm);
	}
}
