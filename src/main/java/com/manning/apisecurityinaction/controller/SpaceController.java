package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.*;
import spark.*;

public class SpaceController {
	private final Database database;
	public SpaceController(Database database) {
		this.database = database;
	}

	public JSONObject createSpace(Request request, Response response) {
		var json = new JSONObject(request.body());
		var spaceName = json.getString("name");
		if (spaceName.length() > 255) {
			throw new IllegalArgumentException("space name too long");
		}
		var owner = json.getString("owner");
		var subject = request.attribute("subject");
		if (!owner.equals(subject)) {
			throw new IllegalArgumentException("owner must match authenticated user");
		}
		if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
//			throw new IllegalArgumentException("invalid username: " + owner);
			// Avoid including user input in error responses as a matter of practice.
			// See chapter 2.6.3.
			throw new IllegalArgumentException("invalid username");
		}

		return database.withTransaction(tx -> {
			var spaceId = database.findUniqueLong(
				"SELECT NEXT VALUE FOR space_id_seq;");
			// WARNING: This next line of code is vulnerable to SQL injection.
			database.updateUnique(
				"INSERT INTO spaces(space_id, name, owner) " +
					"VALUES(" + spaceId + ", '" + spaceName +
					"', '" + owner + "');");
			// Avoid SQL injection attacks with PreparedStatement placeholders for user input.
			/*
			database.updateUnique(
				"INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);",
					spaceId, spaceName, owner);
			*/

			// Set response headers.
			response.status(201);
			response.header("Location", "/spaces/" + spaceId);

			return new JSONObject()
				.put("name", spaceName)
				.put("uri", "/spaces/" + spaceId);
		});
	}
}
