function getCap(url, callback) {
	let capUrl = new URL(url);
	let token = capUrl.hash.substring(1); // Extract token from fragment.
	capUrl.hash = ''; // "Blank out" fragment.
	capUrl.search = '?access_token=' + token; // Set URI query parameter for capability token.

	return fetch(capUrl.href) // Call API with capability URI.
	.then(response => response.json())
	.then(callback)
	.catch(err => console.error('Error: ', err));
}
