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
		var owner = json.getString("owner");

		return database.withTransaction(tx -> {
			var spaceId = database.findUniqueLong(
				"SELECT NEXT VALUE FOR space_id_seq;");
			// WARNING: This next line of code is vulnerable to SQL injection.
			database.updateUnique(
				"INSERT INTO spaces(space_id, name, owner) " +
					"VALUES(" + spaceId + ", '" + spaceName +
					"', '" + owner + "');");

			// Set response headers.
			response.status(201);
			response.header("Location", "/spaces/" + spaceId);

			return new JSONObject()
				.put("name", spaceName)
				.put("uri", "/spaces/" + spaceId);
		});
	}
}
