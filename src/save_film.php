<?php


require_once "validation/newFilmValidation.php";
require_once "models/film.php";

session_start();

if (!isset($_SESSION['user_name']) && !$_SESSION['is_moderator']) {
    header('Location: /index.php');
    die();
}

$poster = $_FILES['poster'];
if ($poster['error'] != UPLOAD_ERR_OK) {
    echo json_encode(['errors' => ["Poster loading error: ".$error]]);
    die();
}

$validator = new FilmValidation($_POST, $poster);
if (!$validator->isValid()) {
    echo json_encode(['errors' => $validator->getErrors()]);
    die();
}

$title = $_POST['title'];
$description = $_POST['description'];
$trailer_url = $_POST['trailer_url'];

try {
    $film_pdo = new Film();
} catch (Exception $exception) {
    echo json_encode(['errors' => ["DB connection error: " . $exception->getMessage()]], JSON_UNESCAPED_UNICODE);
    die();
}

$extension = pathinfo($poster['name'])['extension'];
$newRelativePath = '/posters/'.uniqid().'.'.$extension;

if (!move_uploaded_file($poster["tmp_name"], $_SERVER['DOCUMENT_ROOT'].$newRelativePath)) {
    echo json_encode(['errors' => ["Poster loading error"]], );
    die();
}

$film_id = $film_pdo->save($_SESSION["user_id"], $title, $description, $newRelativePath, $trailer_url);
echo $film_id;

echo json_encode([
    'success' => true,
    'card_id' => $film_id]);
