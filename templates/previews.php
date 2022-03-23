<?php

if ($params['film_cards']->rowCount() > 0):
    while ($card = $params['film_cards']->fetch(PDO::FETCH_ASSOC)): ?>
    	<div class="card card-block__item" data-id=<?= $card['id'] ?>>
    		<a class="card__title" href= <?= "/details.php?cardid=" . $card['id'] ?>> <?= $card['name'] ?> </a>
    		<div class="card__description"> Добавлено: <?= $card['date_create'] ?> </div>
    		<img src=<?= $card['poster_url'] ?> alt="тут должна быть картинка" class="img"></img>
            <button class="btn card__button" onclick="document.location='<?='/details.php?cardid=' . $card['id'] ?>'"> Смотреть </button>
    	</div>
    <?php endwhile; ?>
<?php endif; ?>
