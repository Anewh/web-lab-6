<!doctype html>
<html>
	<head>
		<title>Мяу-Ъюъ</title>
		<meta charset="utf-8">
		<link rel="stylesheet" type="text/css" href="../css/style.css"/>
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">

		<?php if (!isset($_SESSION['user_name'])): ?>
 			<script type="text/javascript" src="js/popups.js" defer></script>

 		<?php else: ?>
  			<script type="text/javascript" src="js/after_login.js" defer></script>

 		<?php endif; ?>

		<script type="module" src="js/pages_loading.js" defer></script>
		<script type="module" src="js/comments_loading.js" defer></script>
	</head>
	<body>
	<div class="wrapper">
		
		<?php require_once 'fragments/header.php'; ?>

		<div class="page-title">
		</div>
		<main class="main">
			<?php if ($params['card']->rowCount() === 0): ?> 
				<p class="not-found"> Нет подробной информации по этому фильму </p>

			<?php else:
                $card = $params['card']->fetch(PDO::FETCH_ASSOC);?>
				<div id="filmDetails" class="details" data-id=<?= $id ?>>
					<img src=<?= $card['poster_url'] ?> alt="тут должна быть картинка" class="details__img">

					<div class="details-text-content">
						<div class="details__title"><?= $card['film_name'] ?></div>
						<div class="details__author"><?= $card['author_name'] ?></div>
						<div class="details__date"><?= $card['date_create'] ?></div>
						<div class="details__description"><?= $card['discription'] ?></div>
					</div>
					<?php if (!empty($card['source'])): ?> 
					<div class="trailer-container">
						<iframe width="560" height="315" src=<?= $card['source'] ?> title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

					</div>
					<?php endif; ?>
				</div>
				<div class="comments__wrapper">
					<div class="comments">
						<div class="comments__form"></div>
						<div class="comments__content" id='commentsBlock'>
							<!-- ajax  -->
						</div>
						<div class="loading-gif__wrapper" id="loadingGifWrapper">
								<img class="loading-gif" src="./resources/loader.gif" alt="Раньше здесь был мат">
						</div>
					</div>
				</div>
			<?php endif; ?>
		</main>

		<?php require_once 'fragments/footer.php'; ?>
		
	</div>

	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	</body>
</html>
