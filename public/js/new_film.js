let new_film_submit = document.getElementById("newFilmSubmit");
let new_film = document.getElementById("newFilm");

new_film.addEventListener('submit', function (event) {
  event.preventDefault();

  let poster = document.getElementById("newFilmPoster").files[0];

  if (!poster) {
    displayError(new_film_submit, "Choose file");
    return;
  }

  if (poster.type != "image/jpeg") {
    displayError(new_film_submit, "This file has unsupported type");
    return;
  }

  let new_film_data = new FormData();
  new_film_data.append('title', new_film.title.value);
  new_film_data.append('description', new_film.description.value);
  new_film_data.append('poster', poster);
  new_film_data.append('trailer_url', new_film.trailer_url.value);

  fetch('/film/create', {
       method: 'POST',
       body: new_film_data
    }
  )
  .then(response => response.json())
  .then(result => {
    if (result.errors) {
      displayError(new_film_submit, result.errors);

    } else {
      location.href = "/film/" + result.card_id;
    }
  })
  .catch(error => console.log(error));
});

function displayError(element, text) {
  let form_error = document.getElementById("formError");
  form_error.innerHTML = text;
  form_error.style.display = "block";
  element.after(form_error);
}
