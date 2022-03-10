<?php

require_once 'pdo.php'; 

class Comment extends FilmsPdo
{
    public function getCommentsByFilmId($film_id, $last_id, $count)
    {
        if ($last_id != 0) {
            $sql = 'SELECT c.id AS comment_id, c.content, c.`date`, u.name, u.avatar_url
                    FROM comments AS c INNER JOIN users AS u ON c.author_id = u.id 
                    WHERE c.film_id = :film_id && c.id < :last_id
                    ORDER BY c.`date` DESC
                    LIMIT :count';

            $comments = $this->films_pdo->prepare($sql);
            $comments->bindValue(':last_id', $last_id, PDO::PARAM_INT);
        } else {
            $sql = 'SELECT c.id AS comment_id, c.content, c.`date`, u.name, u.avatar_url
                    FROM comments AS c INNER JOIN users AS u ON c.author_id = u.id 
                    WHERE c.film_id = :film_id
                    ORDER BY c.`date` DESC
                    LIMIT :count';

            $comments = $this->films_pdo->prepare($sql);
        }

        $comments->bindValue(':film_id', $film_id, PDO::PARAM_INT);
        $comments->bindValue(':count', $count, PDO::PARAM_INT);

        $comments->execute();

        return $comments;
    }

    public function addComment($author_id, $film_id, $content, $date)
    {
        $cuurent_date = date("Y/m/d");
        $save_content = htmlspecialchars($content);

        try {
            $sql = "INSERT INTO comments(`author_id`, `film_id`, `content`, `date`)
                    VALUES (:author_id, :film_id, :save_content, :current_date)";

            $comment = $this->films_pdo->prepare($sql);

            $comment->bindValue(":author_id", $author_id);
            $comment->bindValue(":film_id", $film_id);
            $comment->bindValue(":save_content", $save_content);
            $comment->bindValue(":current_date", $current_date);

            $comment->execute();
        } catch (PDOException $e) {
            echo $e->getMessage();
            return false;
        }
        return true;
    }
}
