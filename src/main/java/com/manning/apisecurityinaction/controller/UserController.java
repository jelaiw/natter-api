package com.manning.apisecurityinaction.controller;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.Filter;
import static spark.Spark.halt;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class UserController {
	private static final String USERNAME_PATTERN = "[a-zA-Z][a-zA-Z0-9]{1,29}";

	private final Database database;

	public UserController(Database database) {
		this.database = database;
	}

	public void lookupPermissions(Request request, Response response) {
		requireAuthentication(request, response);
		var spaceId = Long.parseLong(request.params(":spaceId"));
		var username = (String) request.attribute("subject");

		var perms = database.findOptional(String.class, "SELECT rp.perms FROM role_permissions rp JOIN user_roles ur ON rp.role_id = ur.role_id WHERE ur.space_id = ? AND ur.user_id = ?", spaceId, username).orElse("");
		request.attribute("perms", perms);
	}

	public Filter requirePermission(String method, String permission) {
		return (request, response) -> {
			// Ignore requests that don't match the request method.
			if (!method.equalsIgnoreCase(request.requestMethod())) {
				return;
			}

			var perms = request.<String>attribute("perms");
			if (!perms.contains(permission)) {
				halt(403);
			}
		};
	}

	public void requireAuthentication(Request request, Response response) {
		if (request.attribute("subject") == null) {
			response.header("WWW-Authenticate", "Bearer");
			halt(401);
		}
	}

	public void authenticate(Request request, Response response) {
		var authHeader = request.headers("Authorization");
		if (authHeader == null || !authHeader.startsWith("Basic ")) {
			return;
		}

		var offset = "Basic ".length();
		// See https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/Base64.html.
		var credentials = new String(Base64.getDecoder().decode(
			authHeader.substring(offset)), StandardCharsets.UTF_8);

		var components = credentials.split(":", 2);
		if (components.length != 2) {
			throw new IllegalArgumentException("invalid auth header");
		}

		var username = components[0];
		var password = components[1];

		if (!username.matches(USERNAME_PATTERN)) {
			throw new IllegalArgumentException("invalid username");
		}

		var hash = database.findOptional(String.class, "SELECT pw_hash FROM users WHERE user_id = ?", username);
		if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
			request.attribute("subject", username);
		}
	}

	public JSONObject registerUser(Request request, Response response) throws Exception {
		var json = new JSONObject(request.body());
		var username = json.getString("username");
		var password = json.getString("password");

		if (!username.matches(USERNAME_PATTERN)) {
			throw new IllegalArgumentException("invalid username");
		}
		if (password.length() < 8) {
			throw new IllegalArgumentException("password must be at least 8 characters in length");
		}

		// See https://words.filippo.io/the-scrypt-parameters/ for more on scrypt parameter selection.
		var hash = SCryptUtil.scrypt(password, 32768, 8, 1);
		database.updateUnique("INSERT INTO users(user_id, pw_hash) VALUES(?, ?)", username, hash);

		response.status(201);
		response.header("Location", "/users/" + username);
		return new JSONObject().put("username", username);
	}
}
