<!doctype html>
<html>
	<head>
		<title>Мяу-Ъюъ</title>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">

		<link rel="stylesheet" type="text/css" href="css/style.css"/>

		<?php if (!isset($_SESSION['user_name'])): ?>
 			<script type="text/javascript" src="js/popups.js" defer></script>

 		<?php else: ?>
  			<script type="text/javascript" src="js/after_login.js" defer></script>
  			<script type="text/javascript" src="js/new_film.js" defer></script>
  			<link rel="stylesheet" type="text/css" href="css/new_film_page.css"/>

 		<?php endif; ?>

 		<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	</head>
	<body>
	<div class="wrapper">
		
		<?php require_once 'fragments/header.php'; ?>

		<div class="page-title"></div>
		<main class="main">
			<?php if (isset($_SESSION['user_name']) && $_SESSION['is_moderator']): ?>
				<div class="film-form__wrapper">
					<form name="newFilm" class="film-form" id="newFilm" method="post" enctype="multipart/form-data">
						<label for="newFilmTitle" class="film-form__label"> Название фильма </label>
						<input id="newFilmTitle" name="title" type="text" required>
						
						<label for="newFilmDescription" class="film-form__label"> Текст обзора </label>
						<input id="newFilmDescription" name="description" type="text" class="film-form__description" required>
						
						<label for="newFilmPoster" class="film-form__label"> Постер </label>
						<p class="film-form__text">Картинка формата .jpeg размером не более 3 МБ</p>
						<input id="newFilmPoster" name="poster" type="file" name="file" class="film-form__file" 
						accept=".jpg, .jpeg" required>
						
						<label for="newFilmUrl" class="film-form__label" placeholder="https://www.youtube.com/" > Ссылка на трейлер Youtube </label>
						<input id="newFilmUrl" name="trailer_url" type="url" >

						<div class="g-recaptcha__wrapper">
				     		<div class="g-recaptcha" data-sitekey="6LdOQQodAAAAAAcUczjcCgzENgGd-_9uW1tYwg5s"></div>
				     	</div>

					    <input id="newFilmSubmit" type="submit" name="submit" class="film-form_submit btn" value="Добавить новый обзор">
					</form>
				</div>
			<?php else: ?>
				<p class="not-logged-alert">У вас нет доступа к этой части сайта</p>
			<?php endif; ?>
		</main>

		<?php require_once 'fragments/footer.php'; ?>
		
	</div>
	<p class="form__error" id="formError"></p>
	</body>
</html>
