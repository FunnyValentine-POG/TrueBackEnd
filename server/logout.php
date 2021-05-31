<?php
  session_start();
  $_SESSION['id'] = 0;
  $_SESSION['username'] = "";
  $_SESSION['password'] = "";
  include_once("csdl.php");
  $caulenh = "delete from chitietgiohang";
  TruyVan($caulenh);
?>
