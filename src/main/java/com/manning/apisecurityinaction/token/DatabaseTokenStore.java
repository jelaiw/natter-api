package com.manning.apisecurityinaction.token;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;

import java.util.Optional;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class DatabaseTokenStore implements TokenStore {
	private final Database database;
	private final SecureRandom secureRandom;

	public DatabaseTokenStore(Database database) {
		this.database = database;
		this.secureRandom = new SecureRandom();

		// Clean up expired tokens every 10 min (after an initial 10-min delay).
		Executors.newSingleThreadScheduledExecutor()
			.scheduleAtFixedRate(this::deleteExpiredTokens, 10, 10, TimeUnit.MINUTES);
	}

	// See chapter 5.2.1 for discussion on how to generate secure token IDs.
	private String randomId() {
		var bytes = new byte[20];
		secureRandom.nextBytes(bytes);
		return Base64url.encode(bytes);
	}

	@Override
	public String create(Request request, Token token) {
		var tokenId = randomId();
		var attrs = new JSONObject(token.attributes).toString();

		database.updateUnique("INSERT INTO tokens(token_id, user_id, expiry, attributes) VALUES (?, ?, ?, ?)",
			tokenId, token.username, token.expiry, attrs);

		return tokenId;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		return database.findOptional(this::readToken,
			"SELECT user_id, expiry, attributes FROM tokens WHERE token_id = ?", tokenId);
	}

	// Helper to reconstruct token from JSON.
	private Token readToken(ResultSet resultSet) throws SQLException {
		var username = resultSet.getString(1);
		var expiry = resultSet.getTimestamp(2).toInstant();
		var json = new JSONObject(resultSet.getString(3));

		var token = new Token(expiry, username);
		for (var key : json.keySet()) {
			token.attributes.put(key, json.getString(key));
		}
		return token;
	}

	@Override
	public void revoke(Request request, String tokenId) {
		// Revoke a token on logout by deleting it from the database.
		database.update("DELETE FROM tokens WHERE token_id = ?", tokenId);
	}

	public void deleteExpiredTokens() {
		database.update("DELETE FROM tokens WHERE expiry < current_timestamp");
	}
}
