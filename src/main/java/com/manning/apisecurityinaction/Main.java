package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.*;
import static spark.Spark.*;

import java.nio.file.*;

import org.dalesbred.*;
import org.h2.jdbcx.*;
import org.json.*;

import org.dalesbred.result.EmptyResultException;
import spark.Request;
import spark.Response;

import com.google.common.util.concurrent.RateLimiter;

public class Main {
	public static void main(String... args) throws Exception {
		// See docs at https://sparkjava.com/documentation#embedded-web-server.
		secure("localhost.p12", "changeit", null, null);

		var datasource = JdbcConnectionPool.create(
			"jdbc:h2:mem:natter", "natter", "password");
		var database = Database.forDataSource(datasource);
		createTables(database);
		// Implement least privilege with natter_api_user.
		datasource = JdbcConnectionPool.create(
			"jdbc:h2:mem:natter", "natter_api_user", "password");
		database = Database.forDataSource(datasource);

		var spaceController = new SpaceController(database);
		// Wire up /spaces post to create a new space.
		post("/spaces", spaceController::createSpace);

		var userController = new UserController(database);
		// Wire up /users post to register a new user.
		post("/users", userController::registerUser);

		// Authenticate users before all API calls.
		before(userController::authenticate);

		// Perform audit logging after authn (but before authz).
		var auditController = new AuditController(database);
		before(auditController::auditRequestStart);
		afterAfter(auditController::auditRequestEnd);

		// Require authentication for /spaces endpoint.
		before("/spaces", userController::requireAuthentication);

		// Wire up post message with write permission.
		before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
		post("/spaces/:spaceId/messages", spaceController::postMessage);

		// Wire up read message with read permission.
		before("/spaces/:spaceId/messages/*", userController.requirePermission("GET", "r"));
		get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);

		// Wire up find messages with write permission.
		before("/spaces/:spaceId/messages", userController.requirePermission("GET", "r"));
		get("/spaces/:spaceId/messages", spaceController::findMessages);

		var moderatorController = new ModeratorController(database);

		// Wire up delete post with delete permission.
		before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));
		delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);

		// Wire up add member with read permission.
		before("/spaces/:spaceId/members", userController.requirePermission("POST", "r"));
		post("/spaces/:spaceId/members", spaceController::addMember);

		// Wire up /logs get to show audit logs.
		get("/logs", auditController::readAuditLog);

		// Implement basic rate-limiting.
		// See https://guava.dev/releases/29.0-jre/api/docs/com/google/common/util/concurrent/RateLimiter.html.
		var rateLimiter = RateLimiter.create(2.0d);
		before((request, response) -> {
			if (!rateLimiter.tryAcquire()) {
				response.header("Retry-After", "2");
				halt(429);
			}
		});

		// Avoid leaking server information in header. Is there value in a misleading value here?
		afterAfter((request, response) -> response.header("Server", ""));
		// Disable reflected XSS protection in web browser.
		afterAfter((request, response) -> response.header("X-XSS-Protection", "0"));

		// Respond with 415 Unsupported Media Type for anything besides "application/json" content type.
		before(((request, response) -> {
			if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
				halt(415, new JSONObject().put("error", "Only application/json supported.").toString());
			}
		}));

		// Harden endpoint against XSS (see Table 2.1 in section 2.6.2 and 2.6.3 for further detail).
		afterAfter((request, response) -> {
			response.type("application/json;charset=utf-8");
			response.header("X-Content-Type-Options", "nosniff");
			response.header("X-Frame-Options", "DENY");
			response.header("Cache-Control", "no-store");
			response.header("Content-Security-Policy",
				"default-src 'none'; frame-ancestors 'none'; sandbox");
			// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security.
//			response.header("Strict-Transport-Security", "max-age=31536000"); // 1 year.
			response.header("Strict-Transport-Security", "max-age=7200"); // 2 hours for testing, see 3.4.2 tip.
		});

		internalServerError(new JSONObject()
			.put("error", "internal server error").toString());
		notFound(new JSONObject()
			.put("error", "not found").toString());

		exception(IllegalArgumentException.class, Main::badRequest);
		exception(JSONException.class, Main::badRequest);
		exception(EmptyResultException.class, (e, request, response) -> response.status(404));
	}

	private static void createTables(Database database) throws Exception {
		var path = Paths.get(
			Main.class.getResource("/schema.sql").toURI());
		database.update(Files.readString(path));
	}

	private static void badRequest(Exception exception, Request request, Response response) {
		response.status(400);
		response.body("{\"error\": \"" + exception.getMessage() + "\"}");
	}
}

