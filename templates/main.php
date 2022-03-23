<?php session_start(); ?>
<!doctype html>
<html>
	<head>
		<title>Лаба №2</title>
		<meta charset="utf-8">
		<link rel="stylesheet" type="text/css" href="css/style.css"/>
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">

		<?php if (!isset($_SESSION['user_name'])): ?>
 			<script type="text/javascript" src="js/popups.js" defer></script>

 		<?php else: ?>
  			<script type="text/javascript" src="js/after_login.js" defer></script>

 		<?php endif; ?>

		<script type="module" src="js/pages_loading.js" defer></script>
		<script type="module" src="js/previews_loading.js" defer></script>
    	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	</head>
	<body>
	<div class="wrapper">

		<?php require_once 'fragments\header.php'; ?>
		

		<div class="page-title">
			<h1>Find right movie for evening </h1>
			<div class="page-text"><b>Discuss new or favorite movies with other moviegoers ;)<br>Send good films for your friend</b></div>
			<button class=" btn page-title__btn" type="button">Start searching</button>
		</div>
		<main class="main">
			<div id="cardsBlock" class="card-block" data-lastid="0">
				<!-- ajax  -->
			</div>
			<div class="loading-gif__wrapper" id="loadingGifWrapper">
					<img class="loading-gif" src="./resources/loader.gif" alt="Раньше здесь был мат">
			</div>
		</main>

		<?php require_once 'fragments\footer.php'; ?>

	</div>
	</body>
</html>
