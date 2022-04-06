<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use App\Models\Comment;

class CommentsController extends BaseController
{
    public function getComments(array $parameters)
    {
        $film_id = intval(@$_GET['filmid']);
        $last_id = intval(@$_GET['lastid']);

        if (!is_numeric($last_id) || !is_numeric($film_id) || $film_id <= 0) {
            $response =[
                "status" =>false,
                "errors" => ["Bad id"]
            ];
            return (new Response())->setContent(json_encode($response))
            ->headers->set('Location', '/')->setStatusCode(404);
        }

        $comment_pdo = new Comment();
        $comments = $comment_pdo->getCommentsByFilmId($film_id, $last_id, 10);
        return $this->renderTemplate('comments.php', ['comments'=> $comments]);
    }
}