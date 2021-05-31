<?php
function TruyVan($caulenh)
{
  $dbh = new PDO('mysql:host=localhost;dbname=bangear', 'root', '');
  $dbh->query("set names utf8");
  $bang = $dbh->query($caulenh);
  return $bang;
}
