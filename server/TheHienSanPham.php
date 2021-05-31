<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js" type="text/javascript"></script>
<script>
  $(document).ready(function() {
    $(".btn_loaisanpham").click(function() {
      maloai = $(this).attr('id');
      $(".dssp").load("../server/TheHienSanPham.php", {
        maloai: maloai
      });
    });
    $(".btn_addcart").click(function() {
      masanpham = $(this).attr('id');
      magiohang = 1;
      $.post("../server/AddToCart.php", {
        magiohang: magiohang,
        masanpham: masanpham
      }, function(data) {
        alert("Add " + masanpham + '\n' + data);
      });
    });
  });
</script>

<?php
include_once("csdl.php");
$maloai = 0;
if (isset($_REQUEST["maloai"]))
  $maloai = $_REQUEST["maloai"];
if ($maloai == 0)
  $caulenh = "Select * from loaisanpham";
else
  $caulenh = "Select * from loaisanpham where maloai=" . $maloai;
$dsloaisanpham = TruyVan($caulenh);
foreach ($dsloaisanpham as $loaisanpham) {
  if ($maloai == 0) {
    echo '<h2 class="Product-title" style="margin-top: 100px">' . $loaisanpham[1] . '<a id=' . $loaisanpham[0] . ' class= "btn_loaisanpham" style="float: right; text-decoration: underline; font-weight: bold" href="#' . $loaisanpham[1] . '">Xem thêm</a></h2><div style="margin-top: 50px" class="grid-container">';
    $caulenh = "Select * from sanpham where loaisanpham=" . $loaisanpham[0] . " limit 4";
  } else {
    echo '<h2 class="Product-title" style="margin-top: 100px">' . $loaisanpham[1] . '<a id=0 class= "btn_loaisanpham" style="float: right; text-decoration: underline; font-weight: bold"  href="#">Trở Lại</a></h2><div style="margin-top: 50px" class="grid-container">';
    $caulenh = "Select * from sanpham where loaisanpham=" . $loaisanpham[0];
  }
  $dssanpham = TruyVan($caulenh);
  foreach ($dssanpham as $sanpham) {
    $num = number_format($sanpham[4]);
    echo '<div class="Card"><img src="' . $sanpham[3] . '" alt="' . $sanpham[1] . '" style="width: 200px; height: 200px"/><h4>' . $sanpham[1] . '</h4><p class="price">' . $num . '₫</p><p>' . $sanpham[5] . '</p><p><button id=' . $sanpham[0] . ' class="btn_addcart">Add to Cart</button></p></div>';
  }
  echo '</div>';
}
?>