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
import java.net.URI;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.io.IOException;
import org.jsoup.nodes.Document;
import static org.jsoup.Connection.Method.GET;

public class LinkPreviewer {
	private static final Logger logger = LoggerFactory.getLogger(LinkPreviewer.class);

	private static boolean isBlockedAddress(String uri) throws UnknownHostException {
		var host = URI.create(uri).getHost();
		for (var ipAddr : InetAddress.getAllByName(host)) {
			if (ipAddr.isLoopbackAddress() || ipAddr.isLinkLocalAddress() || ipAddr.isSiteLocalAddress() || ipAddr.isMulticastAddress() || ipAddr.isAnyLocalAddress() || isUniqueLocalAddress(ipAddr)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isUniqueLocalAddress(InetAddress ipAddr) {
		return ipAddr instanceof Inet6Address
			&& (ipAddr.getAddress()[0] & 0xFF) == 0xFD
			&& (ipAddr.getAddress()[1] & 0xFF) == 0x00;
	}

	private static Document fetch(String url) throws IOException {
		Document doc = null;
		int retries = 0;
		// Loop until URL resolves to a document. Limit number of redirects.
		while (doc == null && retries++ < 9) {
			if (isBlockedAddress(url)) {
				throw new IllegalArgumentException("URL refers to local/private address");
			}
			// Disable automatic redirect handling in Jsoup.
			var response = Jsoup.connect(url).followRedirects(false).timeout(2999).method(GET).execute();
			if (response.statusCode() / 100 == 3) {
				url = response.header("Location");
			}
			else {
				doc = response.parse();
			}
		}
		if (doc == null) throw new IOException("too many redirects");
		return doc;
	}

	public static void main(String...args) {
		afterAfter((request, response) -> {
			response.type("application/json; charset=utf-8");
		});
		get("/preview", (request, response) -> {
			var url = request.queryParams("url");
			var doc = fetch(url);
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
