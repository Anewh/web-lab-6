<?php

require_once 'pdo.php';

class Film extends FilmsPdo
{
    public function getPreviews($last_id, $count)
    {
        if ($last_id != 0) {
            $sql = "SELECT `id`, `name`, `date_create`, `poster_url` FROM `films` WHERE id < :last_id ORDER BY id DESC LIMIT :count";
            $film_cards = $this->films_pdo->prepare($sql);
            $film_cards->bindValue(':last_id', $last_id, PDO::PARAM_INT);
        } else {
            $sql = 'SELECT `id`, `name`, `date_create`, `poster_url` FROM `films` ORDER BY id DESC LIMIT :count';
            $film_cards = $this->films_pdo->prepare($sql);
        }

        $film_cards->bindValue(':count', $count, PDO::PARAM_INT);
        $film_cards->execute();
        return $film_cards;
    }

    public function getFilmDetails($card_id)
    {
        $sql = "SELECT f.id, f.name AS film_name, f.date_create, f.discription, f.poster_url, f.source, u.name AS author_name 
                FROM films AS f INNER JOIN users AS u ON f.author_id = u.id 
                WHERE f.id = :id";

        $card = $this->films_pdo->prepare($sql);

        $card->bindValue(':id', $card_id, PDO::PARAM_INT);

        $card->execute();
        return $card;
    }

    // $userId, $title, $description, $newRelativePath, $trailer_url
    public function save($author_id, $title, $description, $poster_url, $source)
    {
        $save_title = htmlspecialchars($title);
        $date_create = date("Y-m-d H:i:s");
        $save_description = htmlspecialchars($description);
        $save_poster_url = htmlspecialchars($poster_url);
        $save_source = htmlspecialchars($source);

        $sql = "INSERT INTO films (`name`, `date_create`, `author_id`, `discription`, `poster_url`, `source`)
                VALUES (:film_title, :date_create, :author_id, :description, :poster_url, :source);
                SELECT LAST_INSERT_ID();";

        $insert_query = $this->films_pdo->prepare($sql);

        $insert_query->bindValue(":film_title", $save_title);
        $insert_query->bindValue(":date_create", $date_create);
        $insert_query->bindValue(":author_id", $author_id);
        $insert_query->bindValue(":description", $save_description);
        $insert_query->bindValue(":poster_url", $save_poster_url);
        $insert_query->bindValue(":source", $save_source);

        $insert_query->execute();
        return $insert_query->fetch(PDO::FETCH_ASSOC);
    }
}
