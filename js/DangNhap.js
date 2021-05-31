$(document).ready(function()
{
  $(".LoginButton").click(function()
  {
    username = $(".username").val();
    password = $(".password").val();
    $(".FormDangNhap-content").attr('action', window.location.href);
    $.post("../server/DangNhap.php", {username:username, password:password}, function(data)
    {
      alert(data);
    });
  });
});
