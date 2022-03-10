<?php

require_once 'models/user.php';
require_once 'validation/enterValidation.php';

header("Content-Type: application/json");

$data = $_POST;
$validator = new EnterValidation($data);
$validator->isValid();
$errors = $validator->getErrors();

if (!empty($errors)) {
    $response =[
        "status" =>false,
        "errors" => json_encode($errors)
    ];
    echo json_encode($response);
    die();
}
$user_pdo = new User();
$user = $user_pdo->getUserByEmail($data['email']);
$save_password = htmlspecialchars($data['password']);

if (password_verify($save_password, $user['password_hash'])) {
    session_start();
    $_SESSION["user_id"] = $user['id'];
    $_SESSION["user_name"] = $user['name'];
    $_SESSION["is_moderator"] = $user['is_moderator'];
    $response =[
        "status" =>true,
        "user_login"=>$user['email'],
        "is_moderator"=>$user['is_moderator']
    ];
} else {
    array_push($errors, 'wrong password');
    $response =[
        "status" =>false,
        "errors" => json_encode($errors)
    ];
}

echo json_encode($response);
