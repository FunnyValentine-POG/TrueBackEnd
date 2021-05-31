<?php
if (isset($_REQUEST["masanpham"]))
{
  $masanpham=$_REQUEST["masanpham"];
  $magiohang=$_REQUEST["magiohang"];
  include_once("csdl.php");
  $caulenh="Select count(*) from chitietgiohang where masanpham=".$masanpham." and magiohang=".$magiohang;
  $soluong = TruyVan($caulenh)->fetchColumn();
  $caulenh = "Select giatien from sanpham where masanpham=".$masanpham;
  $giatien=TruyVan($caulenh)->fetchColumn();
  if ($soluong[0] == 0)
  {
    $caulenh = sprintf(
      "insert into `chitietgiohang` (`magiohang`, `masanpham`, `soluong`, `dongia`) values(%u, %u, %u, %u)",
      $magiohang,
      $masanpham,
      1,
      $giatien
    );
  }
  else
  {
    $caulenh = sprintf(
      "update `chitietgiohang` set soluong=soluong + 1, dongia=dongia * soluong where magiohang=%u and masanpham=%u",
      $magiohang,
      $masanpham
    );
  }
  TruyVan($caulenh);
}
?>
