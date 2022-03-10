<?php

require_once "models/comment.php";

$film_id = intval(@$_GET['filmid']);
$last_id = intval(@$_GET['lastid']);

if (!is_numeric($last_id) || !is_numeric($film_id) || $film_id <= 0) {
    header('Location: /index.php'); //Не ломай сайт :)
    die();
}

try {
    $comment_pdo = new Comment();
} catch (Exception $exception) {
    echo "Ошибка при подключении к БД: " . $exception->getMessage();
    die();
}

$comments = $comment_pdo->getCommentsByFilmId($film_id, $last_id, 10);

if ($comments->rowCount() > 0):
    while ($comment = $comments->fetch(PDO::FETCH_ASSOC)): ?>
        <div class="comment__item" data-id=<?= $comment['comment_id'] ?>>
            <div class="comment__author">
                    <div class="comment__avatar">
                <img src=<?= $comment['avatar_url'] ?> alt="тут должна быть картинка" class="comment__img">
                </div>
                <p class="comment_author-name"><?= $comment['name'] ?></p>
            </div>
            <p class="comment__date"> <?= $comment['date'] ?> </p>
            <p class="comment__text"><?= $comment['content'] ?></p>
        </div>
    <?php endwhile; ?>
    
<?php endif; ?>