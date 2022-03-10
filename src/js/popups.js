var popup = document.getElementById('popup'), 
    formReg = document.getElementById('form-reg'),
    formIn = document.getElementById('form-in');
    // var isRegistration = true;

document.getElementById('sign-in').addEventListener('click', function() {
  popup.classList.add('open');
  formReg.classList.add('open');
});

document.getElementById('popup-close').addEventListener('click', function() {
  document.getElementById('popup').classList.remove('open');
  if(formReg.classList.contains('open')){
    formReg.classList.remove('open');
  }
  if(formIn.classList.contains('open')){
    formIn.classList.remove('open');
  }
});

document.getElementById('sign-in-form-btn').addEventListener('click', function(){
  if(formReg.classList.contains('open')){
    formReg.classList.remove('open');
    formIn.classList.add('open');
  }
  else if(formIn.classList.contains('open')){
    signInSubmit();
  }
});

document.getElementById('sign-up-form-btn').addEventListener('click', function(){
  if(formIn.classList.contains('open')){
    formIn.classList.remove('open');
    formReg.classList.add('open');
  }
  else if(formReg.classList.contains('open')){
    formRegValidation();
    signUpSubmit();
  }
});

function showError(element, text) {
  let formError = document.getElementById("formError");
  formError.innerHTML = "*" + text;
  formError.style.display = "block";
  element.after(formError);
}

function hideError() {
  document.getElementById("formError").style.display = "none";
}

function formRegValidation(){
    if(formReg.classList.contains('open')){    //лишняя проверка, но не знаю как лучше
        var password = formReg.password.value;
        var password_repeat = formReg.repeat.value;
        if(password!=password_repeat){
          showError(document.getElementById("formReg"), 'passwords must be equals');
    }
  }
}

function formInValidation(){
    if(formIn.classList.contains('open')){      //лишняя проверка, но не знаю как лучше
        var password = formIn.password.value;
        var email = formIn.email.value;
    }
}

function signInSubmit(){
    let loginData = new FormData();

    loginData.append('email', formIn.email.value);
    loginData.append('password', formIn.password.value);

    fetch('enter.php', {
         method: 'POST',
         body: loginData
      }
    )
    .then(response => response.json())
    .then(result => {
      if (result.errors) {
        showError(document.getElementById("formReg"), result.errors);
      } else {
        hideError();
        location.href = location.href;
      }
    })
    .catch(error => console.log(error));
}

formReg.addEventListener('submit', function(event){
  event.preventDefault();
});

formIn.addEventListener('submit', function(event){
  event.preventDefault();
});

function signUpSubmit(){
    let registerData = new FormData();
    registerData.append('name', formReg.name.value);
    registerData.append('email', formReg.email.value);
    registerData.append('phone_number', formReg.phone.value);
    registerData.append('password', formReg.password.value);
  
    fetch('registration.php', {
         method: 'POST',
         body: registerData
      }
    )
    .then(response => response.json())
    .then(result => {
      if (result.errors) {
         showError(document.getElementById("formReg"), result.errors);
      } else {
        hideError();
        location.href = location.href;
      }
    })
    .catch(error => console.log(error));
}