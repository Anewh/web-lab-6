<?php
if ($params['comments']->rowCount() > 0):
    while ($comment = $params['comments']->fetch(PDO::FETCH_ASSOC)): ?>
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