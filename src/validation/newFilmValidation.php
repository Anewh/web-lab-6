<?php

class FilmValidation
{
    private $title;
    private $description;
    private $trailer_url;
    private $poster;

    private $url_pattern = '#((https?)://(\S*?\.\S*?))([\s)\[\]{},;"\':<]|\.\s|$)#i';

    protected $errors=[];

    public function __construct($request, $file)
    {
        $this->title = $request['title'];
        $this->description = $request['description'];
        $this->trailer_url = $request['trailer_url'];
        $this->poster = $file;
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public function isValid()
    {
        return $this->validateDescription() && $this->validateTrailerUrl() && $this->validateTitle() && $this->validatePoster();
    }

    public function validateTitle()
    {
        if (!empty($this->title)) {
            return true;
        } else {
            array_push($this->errors, 'title is empty');
            return false;
        }
    }

    public function validateDescription()
    {
        if (!empty($this->description)) {
            return true;
        } else {
            array_push($this->errors, 'description is empty');
            return false;
        }
    }

    public function validateTrailerUrl()
    {
        if (empty($this->trailer_url)) {
            return true;
        } elseif (preg_match($this->url_pattern, $this->trailer_url) && strlen($this->trailer_url) > 6) {
            return true;
        } else {
            array_push($this->errors, 'trailer_url does not match the pattern');
            return false;
        }
    }

    public function validatePoster()
    {
        $extension = strtolower(pathinfo($this->poster['name'])['extension']) ?? "";
        $type = $this->poster['type'];

        if (!($type == "image/jpeg" && ($extension == 'jpg' || $extension == 'jpeg'))) {
            array_push($this->errors, 'File has unsupported type');
            return false;
        }

        if ($this->poster['size'] > 3 * pow(2, 20)) {
            array_push($this->errors, 'Poster image very large');
            return false;
        }
        return true;
    }
}
