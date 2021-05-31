$(document).ready(function () {
  $("#DangKyButton").click(function () {
    hoten = $("#hoten").val();
    diachi = $("#diachi").val();
    sdt = $("#sdt").val();
    email = $("#email").val();
    username = $("#username").val();
    password = $("#password").val();
    passconfirm = $("#passconfirm").val();
    $.post(
      "../server/DangKy.php",
      {
        hoten: hoten,
        diachi: diachi,
        sdt: sdt,
        email: email,
        username: username,
        password: password,
        passconfirm: passconfirm,
      },
      function (data)
      {
        alert(data);
        if (data == "Đăng ký thành công")
          window.location.href = "../client/TrangChu.php";
      }
    );
  });
});
