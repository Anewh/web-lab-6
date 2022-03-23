<div id="popup" class="popup">
	<div class="popup__body">
		<div class="popup__content">
			<div class="popup-header">
				<img class="logo" src="css/img/2.png">
				<button class="popup__close" id="popup-close">Х</button>
			</div>
		<form class="form-reg" id="form-reg" onSubmit="return formRegValidation()">
		  <div class="form-row">
		    <div class="form-group col-x2">				   
		      <label for="inputName">Name</label>
		      <input name="name" class="form-control" id="inputName" placeholder="Name" pattern="^[А-Яа-яЁё\s\-]+$" required>
		    </div>
		    <div class="form-group col-x2">				   
		      <label for="inputEmail">Email</label>
		      <input name="email" class="form-control" id="inputEmail" placeholder="Email" pattern="^((([0-9A-Za-z]{1}[-0-9A-z\.]{1,}[0-9A-Za-z]{1})|([0-9А-Яа-я]{1}[-0-9А-я\.]{1,}[0-9А-Яа-я]{1}))@([-0-9A-Za-z]{1,}\.){1,2}[-A-Za-z]{2,})$" required>
		    </div>
		  </div>
		  <div class="form-row">
		    <div class="form-group col-x2">
		      <label for="inputPasswordSignUp">Password</label>
		      <input name="password" type="password" class="form-control" id="inputPasswordSignUp" placeholder="Password" required>
		    </div>
		    <div class="form-group col-x2">				   
		      <label for="inputRepeatPassword">Repeat password</label>
		      <input name="repeat" type="password" class="form-control" id="inputRepeatPassword" placeholder="Repeat password"  required>
		    </div>
		  </div>
		  <div class="form-row">
		    <div class="form-group col-x2">
		      <label for="inputPhone">Phone</label>
		      <input name="phone" type="text" class="form-control" id="inputPhone" placeholder="Phone number" pattern="^(\s*)?(\+)?([- _():=+]?\d[- _():=+]?){10,14}(\s*)?$" required>
		    </div>
		  </div>
		  <div class="form-group">
		    <div class="form-check">
		      <input class="form-check-input" type="checkbox" id="gridCheck" required>
		      <label class="form-check-label" for="gridCheck">
		        I have read and agree with the personal data processing policy
		      </label>
	      		<div class="g-recaptcha" data-sitekey="6Lc4lwMdAAAAAM0YfFIG2hBMMn0Pl18lfZOJwmhB"></div>
		    </div>
		  </div>
		  </form>
		<form class="form-in" id="form-in" onSubmit="return formInValidation()">
			<div class="form-row">
		    <div class="form-group col-x2">				   
		      <label for="inputEmailSignIn">Email</label>
		      <input name="email" type="email" class="form-control" id="inputEmailSignIn" placeholder="Email" pattern="^((([0-9A-Za-z]{1}[-0-9A-z\.]{1,}[0-9A-Za-z]{1})|([0-9А-Яа-я]{1}[-0-9А-я\.]{1,}[0-9А-Яа-я]{1}))@([-0-9A-Za-z]{1,}\.){1,2}[-A-Za-z]{2,})$" required>
		    </div>
		    <div class="form-group col-x2">
		      <label for="inputPasswordSignIn">Password</label>
		      <input name="password" type="password" class="form-control" id="inputPasswordSignIn" placeholder="Password" pattern="^.{5,100}[\da-z_-]*[a-z_-][\da-z_-]*$" required>
		    </div>
		    <div class="form-row">
		  		<button class="btn forgot-password-btn">Forgot password</button>
		    </div>
		  </div>				  
		  	<div class="g-recaptcha capcha-reg" data-sitekey="6Lc4lwMdAAAAAM0YfFIG2hBMMn0Pl18lfZOJwmhB" required></div>
		</form>
		<div class="buttons-change">
		  	<button form="form-in" class="btn sign" id="sign-in-form-btn">Sign in</button>
			<button form="form-reg" class="btn sign" id="sign-up-form-btn">Sign up</button>
			<div id="formError" class="form-error"></div>
		</div>
	</div>
</div>