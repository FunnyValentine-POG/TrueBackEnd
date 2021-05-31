CREATE TABLE khachhang
(
    makhachhang int AUTO_INCREMENT PRIMARY KEY,
    hoten varchar(255) NOT NULL,
    diachi varchar(255),
    sdt varchar(255) NOT NULL UNIQUE,
    email varchar(255) NOT NULL,
    username varchar(255) NOT NULL UNIQUE,
    pass varchar(255) NOT NULL
);

CREATE TABLE loaisanpham
(
    maloai int AUTO_INCREMENT PRIMARY KEY,
    tenloai varchar(255) NOT NULL
);

CREATE TABLE sanpham
(
    masanpham int AUTO_INCREMENT PRIMARY KEY,
    tensanpham varchar(255) NOT NULL,
    loaisanpham int NOT NULL,
    hinhanh varchar(255) NOT NULL,
    giatien int NOT NULL,
    thongtinchitiet varchar(255),
    FOREIGN KEY (loaisanpham) REFERENCES loaisanpham(maloai)
);

CREATE TABLE chitietgiohang
(
    magiohang int AUTO_INCREMENT,
    masanpham int NOT NULL,
    soluong int NOT NULL,
    dongia int NOT NULL,
    FOREIGN KEY (masanpham) REFERENCES sanpham(masanpham),
    PRIMARY KEY (magiohang, masanpham)
);

CREATE TABLE chitietdonhang
(
    madonhang int AUTO_INCREMENT,
    masanpham int NOT NULL,
    soluong int NOT NULL,
    dongia int NOT NULL,
    FOREIGN KEY (masanpham) REFERENCES sanpham(masanpham),
    PRIMARY KEY (madonhang, masanpham)
);

CREATE TABLE trangthai
(
    matrangthai int AUTO_INCREMENT PRIMARY KEY,
    tentrangthai varchar(255) NOT NULL
);

CREATE TABLE lichsudathang
(
    madonhang int NOT NULL,
    makhachhang int NOT NULL,
    ngaydathang datetime NOT NULL,
    diachi varchar(255) NOT NULL,
    sdt varchar(255) NOT NULL,
    tongdonhang int NOT NULL,
    ghichu varchar(255),
    trangthai int NOT NULL,
    FOREIGN KEY (madonhang) REFERENCES chitietdonhang(madonhang),
    FOREIGN KEY (makhachhang) REFERENCES khachhang(makhachhang),
    FOREIGN KEY (trangthai) REFERENCES trangtha(matrangthai),
  	PRIMARY KEY (madonhang, makhachhang)
);

INSERT INTO `loaisanpham`(`tenloai`) VALUES ('Bàn Phím');
INSERT INTO `loaisanpham`(`tenloai`) VALUES ('Chuột Gaming');
INSERT INTO `loaisanpham`(`tenloai`) VALUES ('Laptop');
INSERT INTO `loaisanpham`(`tenloai`) VALUES ('Win Bản Quyền');

INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('SteelSeries Apex Pro',1,'https://www.azaudio.vn/Data/Sites/1/Product/10261/azaudio-steelseries-apex-pro-tkl.jpg',4490000,'Switch: OmniPoint');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Razer Huntsman Elite',1,'https://assets3.razerzone.com/wr954gffghfNGNsh7ZDP397w76g=/767x511/https%3A%2F%2Fhybrismediaprod.blob.core.windows.net%2Fsys-master-phoenix-images-container%2Fhc8%2Fh54%2F9081235374110%2FRazer-Huntsman-Elite-gallery-hero.jpg',4990000,'Switch:Opto-Mechanical™ Switches');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Roccat Vulcan 120 Aimo',1,'https://cdn.mos.cms.futurecdn.net/CmLFrg7q8agZcSzKt2WYVH-970-80.jpg.webp',3590000,'Switch:Blue/Orange/Pink');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Alienware Pro Gaming Keyboard AW768',1,'https://cdn.mos.cms.futurecdn.net/Kn5wdCDeN9Fr2cs5VepAQh-970-80.jpg.webp',3290000,'Switch:Blue/Orange/Pink');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Akko 3108 v2',1,'https://product.hstatic.net/1000026716/product/gearvn-ban-phim-akko-3108-v2-one-piece-chopper-akko-switch-1_9cf7a679f0794c8e8ec482a59657c10b.jpg',1490000,'Switch:Blue/Orange/Pink');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('iKBC CD87 PD',1,'https://product.hstatic.net/1000026716/product/ban-phim-ikbc-cd87-pd-tkl_a5c45683d62e4c348579cb54ce37d4de.jpg',1390000,'Switch:Red/Brown/Blue');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Razer Blackwidow Green Switch',1,'https://product.hstatic.net/1000026716/product/razer_blackwidow_a77fb116418d4186b7cb4bb170cd5cb8.jpg',2690000,'Switch:Razer™ Green Mechanical');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Corsair K70 RGB MK.2',1,'https://anphat.com.vn/media/product/27766_corsair_k70_mk2_rgb_low_profile.jpg',3490000,'Switch:Red/Blue/Brown');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Logitech G502',2,'https://xgear.vn/wp-content/uploads/2017/08/G502_hero_1.jpg',1799000,'Logitech G502 Hero');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('BenQ Ec2-A',2,'https://product.hstatic.net/1000131176/product/1-1000x1000_390c2b89de9d43799cd5815e7360c766_master.jpg',1679000,'Zowie BenQ EC2A Optical USB Gaming');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Razer DeathAdder V2',2,'https://hanoicomputercdn.com/media/product/51576_chuot_razer_deathadder_v2_rgb_gaming_mouse_black_rz01_03210100_r3m1_0003_1.jpg',1599000,'Death Adder V2');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('CORSAIR DARK CORE RGB PRO SE',2,'https://www.bkin.vn/wp-content/uploads/2020/08/Corsair-Dark-Core-RGB-Pro-SE.jpg',2489000,'Corsair Dark Core Wireless RGB SE');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Cooler Master MM710',2,'https://hanoicomputercdn.com/media/product/51522_hnc_chuot_choi_game_cooler_master_mm710_black_matte_2.jpg',890000,'Cooler Master MM710 Black');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Steelseries Rival 3',2,'https://www.maxgaming.com/bilder/artiklar/100109.jpg?m=1599391891',1290000,'Steelseries Rival 3 Wireless');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Fuhlen G90',2,'https://product.hstatic.net/1000026716/product/gearvn_fuhlen_g90pro_2e3cda3b0f3a495aa66d8eb7358b6c66.png',450000,'Fuhlen G90 Pro');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Logitech G102 Lightsync',2,'https://phucanhcdn.com/media/product/39104_g102_lightsync_white_ha4.jpg',400000,'Logitech G102 Lightsync RGB White');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('ASUS TUF FX505DT',3,'https://sctt.net.vn/wp-content/uploads/2020/09/18227-asus-tuf-gaming-fx505dt-hn478t-2.jpg',17990000,'ASUS TUF FX505DT HN478T');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('MSI GF63 Thin',3,'https://laptop88.vn/media/product/5664_msi_gf63_thin_9scsr.jpg',19990000,'MSI GF63 Thin 9SCSR 829VN');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Lenovo Legion 5',3,'https://laptop88.vn/media/product/5290_lenovo_legion_5_15imh05_82au004yvn_4.png',25990000,'Lenovo Legion 5 15IMH05 82AU004YVN');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Acer Nitro 5',3,'https://www.tncstore.vn/image/cache/catalog/Avata%20Laptop/Nitro%205%202020-500x500.jpg',25990000,'Acer Nitro 5 AN515 55 77P9');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Asus Vivobook D509DA',3,'https://hanoicomputercdn.com/media/product/56267_d509da__10_.jpg',11990000,'Asus Vivobook D509DA-AMD Ryzen 5');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('LG Gram 14ZD90N',3,'https://hanoicomputercdn.com/media/product/52018_14zd90n_v_ax53a5.png',25789000,'LG Gram 14ZD90N-V.AX53A5');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('MSI Gaming BRAVO 15',3,'https://cdn.cellphones.com.vn/media/catalog/product/cache/7/image/9df78eab33525d08d6e5fb8d27136e95/l/a/laptop-msi-gaming-bravo-15-a4dcr_1_.jpg',17950000,'MSI Gaming BRAVO 15 A4DCR-270VN');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Dell XPS 15 9575',3,'https://bizweb.dktcdn.net/100/143/747/files/dell-1-574ffce9-b4c5-430d-a663-8c3aa0c1c35a.jpg?v=1536914962263',59490000,'Dell XPS 15 9575 70170134(Silver)');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Windows 10 Home',4,'https://salt.tikicdn.com/ts/product/28/42/6e/a6c7a0472d4a73a510e88b2fbc441b8d.png',2890000,'Window Home 10 32bit/64bit');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Windows 10 Pro',4,'https://bizweb.dktcdn.net/100/372/934/products/win-10.png?v=1580786765610',6799000,'Windows 10 Pro 32bit/64bit');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Windows Svr Std 2016',4,'https://thegioibanquyen.com/wp-content/uploads/2016/02/windows-server-2016-standard.jpg',15628000,'Windows Server 2016 Standard');
INSERT INTO `sanpham`(`tensanpham`, `loaisanpham`, `hinhanh`, `giatien`, `thongtinchitiet`)
VALUES ('Windows 10 Education',4,'https://salt.tikicdn.com/ts/product/16/46/07/581f28d0da3fffa3d7215799eb685ece.jpg',370000,'Windows 10 Education');
