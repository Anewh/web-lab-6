import { scrollMore } from './pages_loading.js';


function makeQueryUrl() {
  let filmDetails = document.getElementById('filmDetails');

  let film_id = 0;
  if (filmDetails) {
    film_id = filmDetails.getAttribute('data-id');
  }

  let last_id = 0;
  let last_card = document.getElementsByClassName('comment__item');

  if (last_card) {
    last_card = last_card[last_card.length-1];
    if (last_card)
      last_id = last_card.getAttribute('data-id'); 
  }

  return '/comments.php?filmid=' + film_id + '&lastid=' + last_id;
}

function bindPreviews() {
  scrollMore('cardsBlock', makeQueryUrl, bindPreviews);
}

function bindComments( ) {
  scrollMore('commentsBlock', makeQueryUrl, bindComments);
}

window.addEventListener('DOMContentLoaded', bindComments);
window.addEventListener('scroll', bindComments);
