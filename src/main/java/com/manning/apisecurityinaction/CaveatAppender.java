package com.manning.apisecurityinaction;

import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import static com.github.nitram509.jmacaroons.MacaroonsBuilder.deserialize;

public class CaveatAppender {
	public static void main(String... args) {
		// Parse macaroon (first command-line argument). Create builder.
		var builder = new MacaroonsBuilder(deserialize(args[0]));
		// Add each caveat (provided as other command-line arguments) to builder.
		for (int i = 1; i < args.length; i++) {
			var caveat = args[i];
			builder.add_first_party_caveat(caveat);
		}
		// Print macaroon as a string to standard output.
		System.out.println(builder.getMacaroon().serialize());
	}
}
