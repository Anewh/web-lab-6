<?php

require_once '../vendor/autoload.php';

use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;
use Symfony\Component\Routing\Loader\YamlFileLoader;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;

$request = Request::createFromGlobals();
$session = new Session();
$session->start();
$request->setSession($session);

$fileLocator = new FileLocator([__DIR__ . '/../config']);
$loader = new YamlFileLoader($fileLocator);
$routes = $loader->load('routes.yaml');

$context = new RequestContext('/');

$matcher = new UrlMatcher($routes, $context);
try {
    $route = $matcher->matchRequest($request);
    list($controllerName, $actionName) = explode("::", $route['_controller']);

    $controller = new $controllerName($request);
    $response = $controller->$actionName($route);

    if (!$response instanceof Response) {
        $response = new Response('Ошибка: неверный ответ от контролера', 500);
    }
} catch (ResourceNotFoundException $exception) {
    $response = new Response('Страница не найдена', 404);
} catch (Exception $exception) {
    $response = new Response('Ошибка: ' . $exception->getMessage(), 500);
}
$response->send();