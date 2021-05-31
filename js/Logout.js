$(document).ready(function()
{
  $(".LogoutButton").click(function()
  {
    $.get("../server/logout.php");
  });
});
