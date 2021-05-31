<?php
  session_start();
  if (isset($_REQUEST["username"]))
  {
    include_once("csdl.php");
    $username = $_REQUEST["username"];
    $password = $_REQUEST["password"];
    $caulenh = "Select count(*) from khachhang where (username='".$username."' or email='".$username."') and pass='".$password."'";
    $count = TruyVan($caulenh)->fetchColumn();
    if ($count > 0)
    {
      $caulenh = "Select * from khachhang where (username='".$username."' or email='".$username."') and pass='".$password."'";
      $dsacc = TruyVan($caulenh);
      foreach ($dsacc as $acc)
      {
        $_SESSION["id"] = $acc[0];
        $_SESSION["username"] = $acc[5];
        $_SESSION["password"] = $acc[6];
        echo "Đăng nhập thành công";
      }
    }
    else
      echo "invalid username or password";
  }
?>
