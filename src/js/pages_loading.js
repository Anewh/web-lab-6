var is_page_loading = false;

export function scrollMore(containerId, makeQueryUrl, bindingFunction) {
  let loading_indicator = document.getElementById('loadingGifWrapper');

  if (is_page_loading) {
    return false;
  }
 
  let body = document.body;
  let html = document.documentElement;

  let wt = body.scrollTop;
  let wh = html.scrollHeight;
  let et = loading_indicator.offsetTop;
  let dh = body.scrollHeight;   
 
  if (wt + wh >= et || wh + wt == dh){
    is_page_loading = true;
    document.getElementById('loadingGifWrapper').style.display = "flex";

    var request = new XMLHttpRequest();
    request.open("GET", makeQueryUrl());

    request.onreadystatechange = function() {
      is_page_loading = false;
      document.getElementById('loadingGifWrapper').style.display = "none";
      if(this.readyState === 4 && this.status === 200) {
        if (this.responseText.length !== 0) {
          document.getElementById(containerId).innerHTML += this.responseText;

        } else {
          window.removeEventListener('DOMContentLoaded', bindingFunction);
          window.removeEventListener('scroll', bindingFunction);
          loading_indicator.remove();
        }
      }
    };

    request.send();
  }
}
