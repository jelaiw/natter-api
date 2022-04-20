package com.manning.apisecurityinaction;

import static spark.Spark.*;
import spark.Request;
import spark.Response;
import spark.Filter;
import java.util.Set;

class CorsFilter implements Filter {
	private final Set<String> allowedOrigins;

	CorsFilter(Set<String> allowedOrigins) {
		this.allowedOrigins = allowedOrigins;
	}

	@Override
	public void handle(Request request, Response response) {
		var origin = request.headers("Origin");
		if (origin != null && allowedOrigins.contains(origin)) {
			response.header("Access-Control-Allow-Origin", origin);
			response.header("Access-Control-Allow-Credentials", "true");
			// Tell browser (and network proxies) to only cache the response for this specific origin.
			// See chapter 5.1.2 for further context.
			response.header("Vary", "Origin");
		}

		if (isPreflightRequest(request)) {
			if (origin == null || !allowedOrigins.contains(origin)) {
				halt(403);
			}

			response.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
			response.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
			halt(204);
		}

	}

	private boolean isPreflightRequest(Request request) {
		return "OPTIONS".equals(request.requestMethod()) 
			&& request.headers().contains("Access-Control-Request-Method");
	}
}

