<?php

include "models/pdo.php";

$last_id = intval(@$_GET['lastid']);

if (!is_numeric($last_id)) {
    header('Location: /index.php'); //Не ломай сайт :)
    die();
}

try {
    $films_pdo = new FilmsPdo();
} catch (Exception $exception) {
    echo "Ошибка при подключении к БД: " . $exception->getMessage();
    die();
}

$film_cards = $films_pdo->getPreviews($last_id, 8);

if ($film_cards->rowCount() > 0):
    while ($card = $film_cards->fetch(PDO::FETCH_ASSOC)): ?>

    	<div class="card card-block__item" data-id=<?= $card['id'] ?>>
    		<a class="card__title" href= <?= "/details.php?cardid=" . $card['id'] ?>> <?= $card['name'] ?> </a>
    		<div class="card__description"> Добавлено: <?= $card['date_create'] ?> </div>
    		<img src=<?= $card['poster_url'] ?> alt="тут должна быть картинка" class="img"></img>
            <button class="btn card__button" onclick="document.location='<?='/details.php?cardid=' . $card['id'] ?>'"> Смотреть </button>
    	</div>
    <?php endwhile; ?>
<?php endif; ?>
