<!DOCTYPE html>
<html style="cursor: url(../Cursor/cursor.cur),default;">

<head>
  <meta charset="utf-8" />
  <title>Giỏ Hàng</title>
  <link rel="stylesheet" href="../css/Frame.css" type="text/css" />
  <link rel="stylesheet" href="../css/ColumnThongTin.css" />
  <link rel="stylesheet" href="../css/GioHang.css" />
  <script type="text/javascript" language="javascript" src="../js/Frame.js"></script>
  <script type="text/javascript" language="javascript" src="../js/Giohang.js"></script>
</head>

<body>
  <?php include_once('head.php'); ?>
  <div class="header" style="margin-top: 100px; margin-bottom: 20px">
    <h1>Giỏ hàng</h1>
  </div>
  <div class="TheHienGioHang">
    <?php include_once('../server/TheHienChiTietGioHang.php') ?>
  </div>
  <div class="" align=center>
    <button type="button" name="button" class="ThanhToanButton">Thanh toán</button>
  </div>
  <?php include_once('footer.php'); ?>
</body>

</html>