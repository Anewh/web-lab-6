<?php

class RegistrationValidation
{
    private $name;
    private $email;
    private $password;
    private $phone_number;

    //private $name_pattern = "/^[А-Яа-яЁё\s\-]+$/";
    private $email_pattern = "/^((([0-9A-Za-z]{1}[-0-9A-z\.]{1,}[0-9A-Za-z]{1})|([0-9А-Яа-я]{1}[-0-9А-я\.]{1,}[0-9А-Яа-я]{1}))@([-0-9A-Za-z]{1,}\.){1,2}[-A-Za-z]{2,})$/";
    //private $password_pattern = "/^.{5,100}[\da-z_-]*[a-z_-][\da-z_-]*$/";
    private $phone_patter = "/^(\s*)?(\+)?([- _():=+]?\d[- _():=+]?){10,14}(\s*)?$/";

    protected $errors=[];

    public function __construct($data)
    {
        $this->name = $data['name'];
        $this->email = $data['email'];
        $this->password = $data['password'];
        $this->phone_number = $data['phone_number'];
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public function isValid()
    {
        return $this->validateEmail() && $this->validatePassword() && $this->validateName() && $this->validatePhone();
    }

    public function validateName()
    {
        if (!empty($this->name)) {
            // if(preg_match($this->name_pattern,$this->name)){
            //     return true;
            // }
            // else{
            //     array_push($this->errors,'Name does not match the pattern');
            //     return false;
            // }
        } else {
            array_push($this->errors, 'Name is empty');
            return false;
        }
    }

    public function validateEmail()
    {
        if (!empty($this->email)) {
            if (preg_match($this->email_pattern, $this->email)) {
                return true;
            } else {
                array_push($this->errors, 'Email does not match the pattern');
                return false;
            }
        } else {
            array_push($this->errors, 'Email is empty');
            return false;
        }
    }

    public function validatePassword()
    {
        if (!empty($this->password)) {
            // if(preg_match($this->password_pattern,$this->password) && strlen($this->password) > 6){
            //     return true;
            // }
            // else {
            //     array_push($this->errors, 'Password does not match the pattern');
            //     return false;
            // }
        } else {
            array_push($this->errors, 'Password is empty');
            return false;
        }
    }

    public function validatePhone()
    {
        if (!empty($this->phone_number)) {
            if (preg_match($this->phone_pattern, $this->phone_number)) {
                return true;
            } else {
                array_push($this->errors, 'Phone does not match the pattern');
                return false;
            }
        } else {
            array_push($this->errors, 'Phone is empty');
            return false;
        }
    }
}
