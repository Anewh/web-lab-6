<?php

    session_start();
    $_SESSION = [];
    header("Refresh:0; url=index.php");
