<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js" type="text/javascript"></script>
<script>
  $(document).ready(function() {
    $(".XoaSanPhamButton").click(function() {
      magiohang = $(this).attr('id1');
      masanpham = $(this).attr('id2');
      $.post("../server/XoaGioHang.php", {
        magiohang: magiohang,
        masanpham: masanpham
      }, function(data) {
        $(".TheHienGioHang").load("../server/TheHienChiTietGioHang.php");
      });
    });
  });
</script>
<?php
include_once("csdl.php");
echo "<table id='BangGioHang' class='BangGioHang' border=1><tr><th>Sản phẩm</th><th>Tên sản phẩm</th><th>Số lượng</th><th>Giá tiền</th><th>Xóa</th></tr>";
$caulenh = "Select * from chitietgiohang where magiohang=1";
$chitietgiohang = TruyVan($caulenh);
$tong = 0;
foreach ($chitietgiohang as $chitiet) {
  $tong = $tong + $chitiet[3];
  $caulenh = "Select * from sanpham where masanpham=" . $chitiet[1];
  $sanpham = TruyVan($caulenh);
  foreach ($sanpham as $sp) {
    echo '<tr><td><img src="' . $sp[3] . '" alt="' . $sp[1] . '" style="width: 200px; height: 200px"/></td><td>' . $sp[1] . '</td><td>' . $chitiet[2] . '</td><td>' . number_format($chitiet[3]) . '</td>';
    echo '<td id1=' . $chitiet[0] . ' id2=' . $chitiet[1] . ' align=center class="XoaSanPhamButton"><span style="cursor: pointer">Xóa</span></td></tr>';
  }
}
echo '<tr><td colspan=4>Tổng</td><td>' . number_format($tong) . '</td></tr>';
echo "</table>";
?>