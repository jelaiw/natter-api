package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.*;
import spark.*;

import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.net.http.HttpClient;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;

public class SpaceController {
	private static final Set<String> DEFINED_ROLES = Set.of("owner", "moderator", "member", "observer");

	private final Database database;
	private final CapabilityController capController;

	private final HttpClient httpClient = HttpClient.newHttpClient();
	private final URI linkPreviewService = URI.create("http://natter-link-preview-service:4567");

	public SpaceController(Database database, CapabilityController capController) {
		this.database = database;
		this.capController = capController;
	}

	private JSONObject fetchLinkPreview(String link) {
		var url = linkPreviewService.resolve("/preview?url="
			+ URLEncoder.encode(link, StandardCharsets.UTF_8));
		var request = HttpRequest.newBuilder(url).GET().build();

		try {
			var response = httpClient.send(request, BodyHandlers.ofString());
			if (response.statusCode() == 200) {
				return new JSONObject(response.body());
			}
		}
		catch (Exception e) { // Ignore any thrown exceptions.
		}
		return null;
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

			// Assign owner role to space owner.
			// Comment out for capabilities exercise, see Listing 9.3 for further context.
			/*
			database.updateUnique(
				"INSERT INTO user_roles(space_id, user_id, role_id) VALUES (?, ?, ?)",
				spaceId, owner, "owner");
			*/

			var expiry = Duration.ofDays(999);
			var uri = capController.createUri(request, "/spaces/" + spaceId, "rwd", expiry);
			var messagesUri = capController.createUri(request, "/spaces/" + spaceId + "/messages", "rwd", expiry);
			var messagesReadWriteUri = capController.createUri(request, "/spaces/" + spaceId + "/messages", "rw", expiry);
			var messagesReadOnlyUri = capController.createUri(request, "/spaces/" + spaceId + "/messages", "r", expiry);

			// Set response headers.
			response.status(201);
			response.header("Location", uri.toASCIIString());

			return new JSONObject()
				.put("name", spaceName)
				.put("uri", uri)
				.put("messages-rwd", messagesUri)
				.put("messages-rw", messagesReadWriteUri)
				.put("messages-r", messagesReadOnlyUri);
		});
	}

  public JSONObject postMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var json = new JSONObject(request.body());
    var user = json.getString("author");
    if (!user.matches("[a-zA-Z][a-zA-Z0-9]{0,29}")) {
      throw new IllegalArgumentException("invalid username");
    }
    if (!user.equals(request.attribute("subject"))) {
      throw new IllegalArgumentException(
              "author must match authenticated user");
    }
    var message = json.getString("message");
    if (message.length() > 1024) {
      throw new IllegalArgumentException("message is too long");
    }

    return database.withTransaction(tx -> {
      var msgId = database.findUniqueLong(
          "SELECT NEXT VALUE FOR msg_id_seq;");
      database.updateUnique(
          "INSERT INTO messages(space_id, msg_id, msg_time," +
              "author, msg_text) " +
              "VALUES(?, ?, current_timestamp, ?, ?)",
          spaceId, msgId, user, message);

      response.status(201);
      var uri = "/spaces/" + spaceId + "/messages/" + msgId;
      response.header("Location", uri);
      return new JSONObject().put("uri", uri);
    });
  }

  public Message readMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var msgId = Long.parseLong(request.params(":msgId"));

    var message = database.findUnique(Message.class,
        "SELECT space_id, msg_id, author, msg_time, msg_text " +
            "FROM messages WHERE msg_id = ? AND space_id = ?",
        msgId, spaceId);

    response.status(200);
    return message;
  }

  public JSONArray findMessages(Request request, Response response) {
    var since = Instant.now().minus(1, ChronoUnit.DAYS);
    if (request.queryParams("since") != null) {
      since = Instant.parse(request.queryParams("since"));
    }
    var spaceId = Long.parseLong(request.params(":spaceId"));

    var messages = database.findAll(Long.class,
        "SELECT msg_id FROM messages " +
            "WHERE space_id = ? AND msg_time >= ?;",
        spaceId, since);

	// Always base permissions on permissions set for current request.
	var perms = request.<String>attribute("perms").replace("w", "");
	var expiry = Duration.ofDays(999);
    response.status(200);
    return new JSONArray(messages.stream()
        .map(msgId -> "/spaces/" + spaceId + "/messages/" + msgId)
		.map(path -> capController.createUri(request, path, perms, expiry))
        .collect(Collectors.toList()));
  }

  public JSONObject addMember(Request request, Response response) {
    var json = new JSONObject(request.body());
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var userToAdd = json.getString("username");
    var role = json.optString("role", "member");

    if (!DEFINED_ROLES.contains(role)) {
      throw new IllegalArgumentException("invalid role");
    }

    database.updateUnique(
            "INSERT INTO user_roles(space_id, user_id, role_id) " +
                    "VALUES(?, ?, ?)", spaceId, userToAdd, role);

    response.status(200);
    return new JSONObject()
            .put("username", userToAdd)
            .put("role", role);
  }

  public static class Message {
    private final long spaceId;
    private final long msgId;
    private final String author;
    private final Instant time;
    private final String message;
	private final List<JSONObject> links = new ArrayList<>();

    public Message(long spaceId, long msgId, String author,
        Instant time, String message) {
      this.spaceId = spaceId;
      this.msgId = msgId;
      this.author = author;
      this.time = time;
      this.message = message;
    }
    @Override
    public String toString() {
      JSONObject msg = new JSONObject();
      msg.put("uri",
          "/spaces/" + spaceId + "/messages/" + msgId);
      msg.put("author", author);
      msg.put("time", time.toString());
      msg.put("message", message);
      msg.put("links", links);
      return msg.toString();
    }
  }
}
