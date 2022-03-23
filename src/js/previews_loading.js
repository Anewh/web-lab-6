import { scrollMore } from './pages_loading.js';

function makeQueryUrl() {
  var last_id = 0;
  let last_card = document.getElementsByClassName('card-block__item');

  if (last_card) {
    last_card = last_card[last_card.length-1];
    if (last_card)
      last_id = last_card.getAttribute('data-id'); 
  }

  return '/previews.php?lastid=' + last_id;
}

function bindPreviews() {
  scrollMore('cardsBlock', makeQueryUrl, bindPreviews);
}

window.addEventListener('DOMContentLoaded', bindPreviews);
window.addEventListener('scroll', bindPreviews);
