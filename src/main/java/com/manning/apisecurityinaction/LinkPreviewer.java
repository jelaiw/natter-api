package com.manning.apisecurityinaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static spark.Spark.afterAfter;
import static spark.Spark.get;
import static spark.Spark.exception;
import spark.ExceptionHandler;
import org.jsoup.Jsoup;
import org.json.JSONObject;
import java.net.MalformedURLException;
import java.net.UnknownHostException;

public class LinkPreviewer {
	private static final Logger logger = LoggerFactory.getLogger(LinkPreviewer.class);

	public static void main(String...args) {
		afterAfter((request, response) -> {
			response.type("application/json; charset=utf-8");
		});
		get("/preview", (request, response) -> {
			var url = request.queryParams("url");
			var doc = Jsoup.connect(url).timeout(2999).get();
			// Extract desired metadata properties from HTML.
			var title = doc.title();
			var desc = doc.head().selectFirst("meta[property='og:description']");
			var img = doc.head().selectFirst("meta[property='og:image']");

			return new JSONObject()
				.put("url", doc.location())
				.putOpt("title", title)
				.putOpt("description", desc == null ? null : desc.attr("content"))
				.putOpt("image", img == null ? null : img.attr("content"));
		});

		// Return appropriate HTTP status codes if jsoup raises an exception.
		exception(IllegalArgumentException.class, handleException(400));
		exception(MalformedURLException.class, handleException(400));
		exception(Exception.class, handleException(502));
		exception(UnknownHostException.class, handleException(404));
	}

	private static <T extends Exception> ExceptionHandler<T> handleException(int status) {
		return (ex, request, response) -> {
			logger.error("Caught error {} - returning status {}", ex, status);
			response.status(status);
			response.body(new JSONObject().put("status", status).toString());
		};
	}
}
