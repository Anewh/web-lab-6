document.getElementById("review").addEventListener('click', function (event) {
    document.location.href = "/film/create";
});

document.getElementById("logout").addEventListener('click', function (event) {
    fetch('/logout', { method: 'POST' })
    .then(response => response)
    .then(result => {location.href = location.href;})
    .catch(error => console.log(error));
});
