<!DOCTYPE html>
<html style="cursor: url(../Cursor/cursor.cur),default;">
  <head>
    <meta charset="utf-8" />
    <title>Đăng Ký</title>
    <link rel="stylesheet" href="../css/Frame.css" type="text/css" />
    <link rel="stylesheet" href="../css/ColumnThongTin.css" />
    <link rel="stylesheet" href="../css/DangKy.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script
      type="text/javascript"
      language="javascript"
      src="../js/DangKy.js"
    ></script>
    <script
      type="text/javascript"
      language="javascript"
      src="../js/Frame.js"
    ></script>
  </head>
  <body>
    <?php include_once('head.php'); ?>
    <div class="header" style="margin-top: 100px">
      <h1>Thông tin đăng ký</h1>
    </div>
    <div class="FormDangKy">
      <form class="FormDangKy-content" action="TrangChu.php" method="post">
        <div class="container">
          <label for="hoten">Họ và Tên:</label>
          <input type="text" name="hoten" id="hoten" required />
          <label for="diachi">Địa chỉ:</label>
          <input type="text" name="diachi" id="diachi" />
          <label for="sdt">Số điện thoại:</label>
          <input type="text" name="sdt" id="sdt" required />
          <label for="email">Email:</label>
          <input type="email" name="email" id="email" required />
          <label for="username">Username:</label>
          <input type="text" name="username" id="username" required />
          <label for="password">Password:</label>
          <input type="password" name="password" id="password" required />
          <label for="passconfirm">Confirm Password:</label>
          <input type="password" name="passconfirm" id="passconfirm" required />
        </div>
        <div class="container">
          <button type="button" name="button" id="DangKyButton" class="RegisterButton">
            Đăng Ký
          </button>
        </div>
      </form>
    </div>
    <?php include_once('footer.php'); ?>
  </body>
</html>
