<!DOCTYPE html>
<html style="cursor: url(../Cursor/cursor.cur),default;">
  <head>
    <meta charset="utf-8" />
    <title>Danh sách sản phẩm</title>
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"
    />
    <link rel="stylesheet" href="../css/Frame.css" type="text/css" />
    <link rel="stylesheet" href="../css/CardSanPham.css" type="text/css" />
    <link rel="stylesheet" href="../css/ColumnThongTin.css" />
    <script
      type="text/javascript"
      language="javascript"
      src="../js/Frame.js"
    ></script>
    <script
      type="text/javascript"
      language="javascript"
      src="../js/CardSanPham.js"
    ></script>
  </head>
  <body>
    <?php include_once('head.php'); ?>
    <div class="dssp">
      <?php include_once("../server/TheHienSanPham.php");?>
    </div>
    <?php include_once('footer.php'); ?>
  </body>
</html>
