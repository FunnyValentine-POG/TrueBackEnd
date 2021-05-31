<?php
  session_start();
  //
  // alert("");
  if (isset($_SESSION["id"]) && $_SESSION["id"] > 0)
  {
    echo '<div>';
    echo '<div>Welcome '.$_SESSION['username'].'</div>';
    echo '<a style="cursor:pointer" class="LogoutButton" href="">Logout</a>';
    // echo '<button type="button" style="cursor:pointer" class="LogoutButton">Logout</button>';
    echo '</div>';
  }
  else
    echo '<div class="DangNhapButton" style="cursor: pointer" onclick="FormDangNhap()" >Đăng Nhập</div><div id="acount" class=""></div>';
?>
