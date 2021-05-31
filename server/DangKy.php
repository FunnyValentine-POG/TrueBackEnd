<?php
session_start();
if (isset($_REQUEST["hoten"])) {
  if ($_REQUEST["password"] == $_REQUEST["passconfirm"])
  {
    include_once("csdl.php");
    $hoten=$_REQUEST["hoten"];
    $diachi=$_REQUEST["diachi"];
    $sdt=$_REQUEST["sdt"];
    $email=$_REQUEST["email"];
    $username=$_REQUEST["username"];
    $password=$_REQUEST["password"];
    if ($hoten != '' && $sdt != '' && $email != '' && $username != '' && $password != '')
    {
      $caulenh = "Select count(*) from khachhang where username='".$username."' and sdt='".$sdt."'";
      $count = TruyVan($caulenh)->fetchColumn();
      if ($count == 0)
      {
        $caulenh = sprintf(
          "insert into `khachhang` (`hoten`, `diachi`, `sdt`, `email`, `username`, `pass`) values('%s', '%s', '%s', '%s', '%s', '%s')",
          $_REQUEST["hoten"],
          $_REQUEST["diachi"],
          $_REQUEST["sdt"],
          $_REQUEST["email"],
          $_REQUEST["username"],
          $_REQUEST["password"]
        );
        TruyVan($caulenh);
        echo "Đăng ký thành công";
        $caulenh = "Select * from khachhang where username='".$username."' and pass='".$password."'";
        $dsacc = TruyVan($caulenh);
        foreach ($dsacc as $acc)
        {
          $_SESSION["id"] = $acc[0];
          $_SESSION["username"] = $acc[5];
          $_SESSION["password"] = $acc[6];
        }
      }
      else
        echo "Username hoặc SDT đã tồn tại";
    }
    else
      echo "Vui lòng điền đầy đủ thông tin";
  }
}
