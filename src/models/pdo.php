<?php


class FilmsPdo
{
    protected $films_pdo;

    public function __construct()
    {
        if (!($pdoConfig = parse_ini_file('config\\pdo.ini'))) {
            throw new Exception("Ошибка парсинга файла конфигурации", 1);
        }
        $this->films_pdo = new PDO('mysql:host='. $pdoConfig['host'] .';dbname='. $pdoConfig['dbname'], $pdoConfig['login'], $pdoConfig['password']);
    }

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

    // public function getFilmDetails($card_id)
    // {
    //     $sql = "SELECT f.id, f.name AS film_name, f.date_create, f.discription, f.poster_url, f.source, u.name AS author_name
    //             FROM films AS f INNER JOIN users AS u ON f.author_id = u.id
    //             WHERE f.id = :id";

    //     $card = $this->films_pdo->prepare($sql);

    //     $card->bindValue(':id', $card_id, PDO::PARAM_INT);

    //     $card->execute();
    //     return $card;
    // }

    // public function getCommentsByFilmId($film_id, $last_id, $count)
    // {
    //     if ($last_id != 0) {
    //         $sql = 'SELECT c.id AS comment_id, c.content, c.`date`, u.name, u.avatar_url
    //                 FROM comments AS c INNER JOIN users AS u ON c.author_id = u.id
    //                 WHERE c.film_id = :film_id && c.id < :last_id
    //                 ORDER BY c.`date` DESC
    //                 LIMIT :count';

    //         $comments = $this->films_pdo->prepare($sql);
    //         $comments->bindValue(':last_id', $last_id, PDO::PARAM_INT);
    //     } else {
    //         $sql = 'SELECT c.id AS comment_id, c.content, c.`date`, u.name, u.avatar_url
    //                 FROM comments AS c INNER JOIN users AS u ON c.author_id = u.id
    //                 WHERE c.film_id = :film_id
    //                 ORDER BY c.`date` DESC
    //                 LIMIT :count';

    //         $comments = $this->films_pdo->prepare($sql);
    //     }

    //     $comments->bindValue(':film_id', $film_id, PDO::PARAM_INT);
    //     $comments->bindValue(':count', $count, PDO::PARAM_INT);

    //     $comments->execute();

    //     return $comments;
    // }
}
