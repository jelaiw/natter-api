const apiUrl = 'https://localhost:4567';

function login(username, password) {
	// See https://developer.mozilla.org/en-US/docs/Web/API/btoa.
	let credentials = 'Basic ' + btoa(username + ":" + password);

	fetch(apiUrl + '/sessions', {
		method: 'POST',
		// Allow API to set cookies on the response. See chapter 5.1.3 for further detail.
		credentials: 'include',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': credentials
		}
	})
	.then(response => {
		if (response.ok) {
			response.json().then(json => {
				localStorage.setItem('token', json.token);
				window.location.replace('/natter.html');
			});
		}
	})
	.catch(error => console.error('Error logging in: ', error));
}

window.addEventListener('load', function(e) {
	document.getElementById('login').addEventListener('submit', processLoginSubmit);
});

function processLoginSubmit(e) {
	e.preventDefault();

	let username = document.getElementById('username').value;
	let password = document.getElementById('password').value;
	login(username, password);

	return false;
}
