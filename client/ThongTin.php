<!DOCTYPE html>
<html style="cursor: url(../Cursor/cursor.cur),default;">
  <head>
    <meta charset="utf-8" />
    <title>Thông Tin</title>
    <link rel="stylesheet" href="../css/Info.css" />
    <link rel="stylesheet" href="../css/Frame.css" />
    <link rel="stylesheet" href="../css/ColumnThongTin.css" />
    <link rel="stylesheet" href="../css/Slide.css" />
    <link rel="stylesheet" href="../css/Clock.css" />
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"
    />
    <script
      type="text/javascript"
      language="javascript"
      src="../js/Frame.js"
    ></script>
    <script src="../js/Slide.js"></script>
    <script src="../js/Clock.js"></script>
  </head>
  <body>
    <?php include_once('head.php'); ?>
    <div class="header" style="margin-top: 100px">
      <h1>Công Ty Vô Trách Nhiệm 2 Thành Viên</h1>
    </div>
    <div class="row">
      <div class="leftcolumn">
        <div class="card" style="margin-top: 0%;">
          <h1>Thông Tin Trang Web</h1>
          <div>
            <img
              src="../images/1610154939426.jpg"
              alt=""
              style="width: 80%"
              class="center"
            />
          </div>
          <p style="font-size: 20px">
            Thành lập với mục đích làm đồ án môn học cuối HK
          </p>
          <p style="font-size: 20px">Giáo Viên Hướng Dẫn:</p>
          <br /><b
            ><a href="https://courses.uit.edu.vn/user/profile.php?id=8746"
              >Thầy Võ Ngọc Tân</a
            ></b
          >
          <br /><b
            ><a href="https://courses.uit.edu.vn/user/profile.php?id=13651"
              >Thầy Tô Quốc Huy</a
            ></b
          >
        </div>
        <div class="card">
          <h1>Danh Sách Sản Phẩm</h1>
          <div class="fakeimg" style="height: auto; background-color: white">
            <!-- Container for the image gallery -->
            <div class="container">
              <!-- Full-width images with number text -->
              <div class="mySlides">
                <div class="numbertext">1 / 6</div>
                <img
                  src="https://product.hstatic.net/1000026716/product/gearvn-chuot-logitech-g304-lightspeed-wireless-white-1000_e28318985b5049099c4e8381695e810f.jpg"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <div class="mySlides">
                <div class="numbertext">2 / 6</div>
                <img
                  src="https://product.hstatic.net/1000026716/product/ban-phim-ikbc-cd87-pd-tkl_a5c45683d62e4c348579cb54ce37d4de.jpg"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <div class="mySlides">
                <div class="numbertext">3 / 6</div>
                <img
                  src="https://product.hstatic.net/1000026716/product/gearvn.com-laptop-gaming-asus-rog-strix-3_2c6afec395124f70bf7bf0124414df04.jpg"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <div class="mySlides">
                <div class="numbertext">4 / 6</div>
                <img
                  src="https://product.hstatic.net/1000026716/product/gearvn_kw9_00139_de00da0e3ae64f89b81174b8489ec44c.jpg"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <div class="mySlides">
                <div class="numbertext">5 / 6</div>
                <img
                  src="https://www.azaudio.vn/Data/Sites/1/Product/10261/azaudio-steelseries-apex-pro-tkl.jpg"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <div class="mySlides">
                <div class="numbertext">6 / 6</div>
                <img
                  src="https://product.hstatic.net/1000026716/product/gearvn_logitech_g502hero.png"
                  style="width: 40%"
                  class="center"
                />
              </div>

              <!-- Next and previous buttons -->
              <a class="prev" onclick="plusSlides(-1)">&#10094;</a>
              <a class="next" onclick="plusSlides(1)">&#10095;</a>

              <!-- Image text -->
              <div class="caption-container">
                <p id="caption"></p>
              </div>

              <!-- Thumbnail images -->
              <div class="row">
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://product.hstatic.net/1000026716/product/gearvn-chuot-logitech-g304-lightspeed-wireless-white-1000_e28318985b5049099c4e8381695e810f.jpg"
                    style="width: 100%"
                    onclick="currentSlide(1)"
                    alt="Logitech G304 Lightspeed Wireless White"
                  />
                </div>
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://product.hstatic.net/1000026716/product/ban-phim-ikbc-cd87-pd-tkl_a5c45683d62e4c348579cb54ce37d4de.jpg"
                    style="width: 100%"
                    onclick="currentSlide(2)"
                    alt="iKBC CD87 PD"
                  />
                </div>
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://product.hstatic.net/1000026716/product/gearvn.com-laptop-gaming-asus-rog-strix-3_2c6afec395124f70bf7bf0124414df04.jpg"
                    style="width: 100%"
                    onclick="currentSlide(3)"
                    alt="Asus ROG Strix G15 G512"
                  />
                </div>
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://product.hstatic.net/1000026716/product/gearvn_kw9_00139_de00da0e3ae64f89b81174b8489ec44c.jpg"
                    style="width: 100%"
                    onclick="currentSlide(4)"
                    alt="Windows 10 Home 64Bit"
                  />
                </div>
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://www.azaudio.vn/Data/Sites/1/Product/10261/azaudio-steelseries-apex-pro-tkl.jpg"
                    style="width: 100%"
                    onclick="currentSlide(5)"
                    alt="SteelSeries Apex Pro"
                  />
                </div>
                <div class="column">
                  <img
                    class="demo cursor"
                    src="https://product.hstatic.net/1000026716/product/gearvn_logitech_g502hero.png"
                    style="width: 100%"
                    onclick="currentSlide(6)"
                    alt="Logitech G502 Hero"
                  />
                </div>
              </div>
            </div>
          </div>
          <p style="font-size: 20px">Sản Phẩm Giảm Giá SHOOOOOOCK</p>
        </div>
      </div>
      <div class="rightcolumn">
        <div class="card" style="margin-top: 0%;">
          <h2 style="text-align: center">Giới Thiệu Công Ty</h2>
          <div>
            <a href="TrangChu.php"
              ><img
                src="../images/logo.png"
                alt=""
                style="width: 80%"
                class="center"
            /></a>
          </div>
          <p style="text-align: justify">
            Công ty L&L được thành lập vào ngày 31/12/2020. Chủ sở hữu gồm 2
            thành viên Nguyễn Đức Huy Long và đồng sáng lập Nguyễn Thành Lân.
            Công ty tuy còn non trẻ nhưng có kinh nghiệm trong lĩnh vực bán hàng
            đa cấp
          </p>
        </div>
        <div class="card">
          <h3 style="text-align: center">Popular Post</h3>
          <div>
            <img
              src="https://techzones.vn/Data/Sites/1/media/tin-cong-nghe/gaming-gear-l%C3%A0-gi/gaming-gear-techzones-bia.jpg"
              alt=""
              style="width: 300px"
              class="center"
            />
          </div>
          <br />
          <div>
            <a href="../client/DsSanPham.php">
            <img
              src="https://news.gearvn.com/wp-content/uploads/2020/09/67456756767.jpg"
              alt=""
              style="width: 300px"
              class="center"
            /></a>
          </div>
        </div>
        <div class="card" style="height: auto">
          <h3 style="text-align: center">Về Chúng Tôi</h3>
          <p style="text-align: justify">
            <b>Nguyễn Đức Huy Long </b>Mssv:18521034
          </p>
          <p style="text-align: justify">
            <b>Nguyễn Thành Lân </b>Mssv:18520977
          </p>
          <p id="clock" style="text-align: center">8:15:30PM</p>
          <iframe
            width="300"
            height="150"
            src="https://www.youtube.com/embed/Fm3P7WpQR3Y"
            frameborder="0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowfullscreen
            class="center"
            style="margin-top: 15px"
          ></iframe>
        </div>
      </div>
    </div>
    <?php include_once('footer.php'); ?>
  </body>
</html>
