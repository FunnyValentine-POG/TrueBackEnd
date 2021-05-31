<?php
if (isset($_REQUEST["masanpham"]))
{
  $masanpham=$_REQUEST["masanpham"];
  $magiohang=$_REQUEST["magiohang"];
  include_once("csdl.php");
  $caulenh = "delete from chitietgiohang where magiohang=".$magiohang." and masanpham=".$masanpham;
  TruyVan($caulenh);
}
?>
