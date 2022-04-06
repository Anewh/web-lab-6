<?php

namespace App\Models;

class Pdo
{
    protected $films_pdo;

    public function __construct()
    {
        if (!($pdoConfig = parse_ini_file(__DIR__ . '/../../config/pdo.ini'))) {
            throw new Exception("Ошибка парсинга файла конфигурации", 1);
        }
        $this->films_pdo = new PDO('mysql:host='. $pdoConfig['host'] .';dbname='. $pdoConfig['dbname'], $pdoConfig['login'], $pdoConfig['password']);
    }
}
