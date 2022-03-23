<?php

namespace App\Controller;

use App\Controller\BaseController;
use Symfony\Component\HttpFoundation\Response;
use App\Models\Film;

class FilmController extends BaseController
{

    public function getStartPage(array $parameters)
    {
        return $this->renderTemplate('main.php');
    }

    public function createFilm(array $parameters): Response
    {
        $this->prepareUserData();
        $this->prepareFilmData();

        $film_id = $film_pdo->save($this->request->getSession()->
            get("user_id"), $title, $description, $newRelativePath, $trailer_url);
        $response =[
            'success' => true,
            'card_id' => $film_id
        ];
        return (new Response())->setContent(json_encode($response))
        ->headers->set('Content-Type', 'application/json');
    }

    public function getFilmForm(array $parameters): Response
    {
        return $this->renderTemplate('newfilm.php');
    }

    public function getDetailsInformation(array $parameters): Response
    {
        $id = intval(@$_GET['cardid']);

        if (!is_numeric($id)) {
            $response =[
                "status" =>false,
                "errors" => ["Bad id"]
            ];
            return (new Response())->setContent(json_encode($response))
            ->headers->set('Location', '/')->setStatusCode(404);
        }
        $film_pdo = new Film();
        $card = $film_pdo->getFilmDetails($id);
        return $this->renderTemplate('details.php', ['card'=> $card]);
    }    

    public function getPreviewList(array $parameters): Response
    {
        $last_id = intval(@$_GET['lastid']);

        if (!is_numeric($last_id)) {
            $response =[
                "status" =>false,
                "errors" => ["Bad id"]
            ];
            return (new Response())->setContent(json_encode($response))
            ->headers->set('Location', '/')->setStatusCode(404);
        }

        $films_pdo = new Film();
        $film_cards = $films_pdo->getPreviews($last_id, 8);
        return $this->renderTemplate('main.php', ['film_cards'=> $film_cards]);
    }

    protected function prepareFilmData()
    {
        $poster = $this->getRequest()->files->get('poster');
        if ($poster['error'] != UPLOAD_ERR_OK) {
            $response =[
                "status" =>false,
                'errors' => ["Poster loading error: ". $poster['error']]
            ];
            return (new Response())->setContent(json_encode($response));
        }

        $validator = new FilmValidation($request->request->all(), $poster);
        if (!$validator->isValid()) {
            $response =[
                "status" =>false,
                'errors' => $validator->getErrors()
            ];
            return (new Response())->setContent(json_encode($response));
        }

        $title = $this->request->get('title');
        $description = $this->request->get('description');
        $trailer_url = $this->request->get('trailer_url');
        
        $film_pdo = new Film();

        $extension = pathinfo($poster['name'])['extension'];

        $newRelativePath = '/posters/'.uniqid().'.'.$extension;

        if (!move_uploaded_file($poster["tmp_name"], $request->server->get('DOCUMENT_ROOT').$newRelativePath)) {
            $response =[
                "status" =>false,
                'errors' => ["Poster loading error"]
            ];
            return (new Response())->setContent(json_encode($response))
            ->headers->set('Content-Type', 'application/json');//добавить везде applJson, вынести в отдельную функцию
        }
    }

    protected function prepareUserData()
    {
        $session = $this->request->getSession();
        if (!$session->has('user_name') || !$session->has('is_moderator')) {
            $response =[
                "status" =>false,
                "errors" => ["User name or moderator status empty"]
            ];
            return (new Response())->setContent(json_encode($response))
            ->headers->set('Location', '/');
        }
    }
}