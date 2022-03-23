<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class BaseController
{
    protected $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    protected function renderTemplate(string $template, array $params = []): Response
    {
        $templateDir = __DIR__ . '/../../templates/';

        if (!file_exists($templateDir . $template)) {
            throw new \Exception("Template '{$template}' not found");
        }

        ob_start();
        require_once $templateDir . $template;
        $content = ob_get_clean();
        return new Response($content);
    }

    public function htmlSpecialCharsMap(array $parameters): array
    {
        return array_map(
            function ($p) {
               return htmlspecialchars($p);
           },
            $parameters
        );
    }
    
    // public prepareErrorResponse(): Response
    // {

    // }
}