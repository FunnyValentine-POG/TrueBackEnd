<header id="main-menu" class="main-menu">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
  <script type="text/javascript" src="../js/DangNhap.js" language="javascript"></script>
  <script type="text/javascript" src="../js/Logout.js" language="javascript"></script>
  <div class="top-menu">
    <div class="logo">
      <a href="TrangChu.php">
        <img src="../images/logo.png" alt="" width="60px" height="60px" />
      </a>
    </div>
    <div>
      <form action="javascript:void(0)" method="post" class="searchField">
        <div class="selectField">
          <select name="">
            <option value="">All</option>
            <option value="">Bàn Phím</option>
            <option value="">Chuột</option>
            <option value="">Laptop</option>
            <option value="">Win</option>
          </select>
        </div>
        <div class="searchFillField">
          <input id="searchFillField" type="search" name="" placeholder="Search..." />
        </div>
        <div class="searchButton">
          <button type="submit" name="button">
            <i class="fa fa-search"></i>
          </button>
        </div>
      </form>
    </div>
    <div class="accountField">
      <?php include_once("../server/login.php") ?>
      <div class="GioHang">
        <span><a href="GioHang.php">Giỏ Hàng</a></span>
      </div>
    </div>
  </div>
  <div class="bottom-menu">
    <div>
      <div class="ListButton">
        <span style="font-size: 30px; cursor: pointer" onclick="openList()">&#9776; All</span>
      </div>
    </div>
    <div class="AnnounceMenu">
      <a href="ThongTin.php">Thông tin trang web</a>
      <a href="DsSanPham.php">Danh sách sản phẩm</a>
    </div>
  </div>
</header>
<div class="">
  <div id="ListOfProduct" class="ListOfProduct">
    <a href="javascript:void(0)" class="CloseButton" onclick="CloseList()">&times;</a>
    <a href="DsSanPham.php?maloai=1">Bàn Phím</a>
    <a href="DsSanPham.php?maloai=2">Chuột</a>
    <a href="DsSanPham.php?maloai=3">Laptop</a>
    <a href="DsSanPham.php?maloai=4">Win Bản Quyền</a>
  </div>
  <div id="BackgroundOfList" class="BackgroundOfList" onclick="CloseList();CloseFormDangNhap()" style="width: 0%; opacity: 0"></div>
  <div id="FormDangNhap" class="FormDangNhap">
    <form id="FormDangNhap-content" class="FormDangNhap-content animate" action='' method="post">
      <div class="container">
        <label for="username">
          <b>Username</b>
        </label>
        <input type="text" name="username" class="username" placeholder="Username" value="user" required />
        <label for="password">
          <b>Password</b>
        </label>
        <input type="password" name="password" class="password" value="user" placeholder="Password" required />
        <button type="submit" class="LoginButton">Đăng Nhập</button>
        <label>
          <input type="checkbox" name="remember" /> Remember me
        </label>
      </div>
      <div class="container" style="background-color: #111">
        <button type="button" onclick="CloseFormDangNhap()" class="cancelbtn">
          Cancel
        </button>
        <span class="psw"> Forgot <a href="">password?</a> </span>
        <span class="psw" style="margin-right: 20px">
          <a href="DangKy.php">Đăng Ký</a>
        </span>
      </div>
    </form>
  </div>
</div>