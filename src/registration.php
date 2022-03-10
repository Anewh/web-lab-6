<?php

require_once "validation/registrationValidation.php";
require_once "models/User.php";

header("Content-Type: application/json");

$data = $_POST;
$validator = new RegistrationValidation($data);
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

if (!$user_pdo->isFreeEmail($data['email'])) {
    array_push($errors, 'This email is used by another user');
    $response =[
        "status" =>false,
        "errors" => json_encode($errors)
    ];
    echo json_encode($response);
    die();
}

try {
    $user_id = $user_pdo->addUser($data['name'], $data['email'], $data['password'], $data['phone_number']);
} catch (Exception $e) {
    return json_encode($e->getMessage());
}

session_start();
$_SESSION["user_id"]=$user_id;
$_SESSION["user_name"]=$data['name'];
$_SESSION["is_moderator"]=0;
$response = [
    "status" =>true,
    "user_login"=>$data['email'],
    "is_moderator"=>0
];
echo json_encode($response);
