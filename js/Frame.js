function openList() {
  document.getElementById("ListOfProduct").style.width = "200px";
  document.body.style.backgroundColor = "rgba(0,0,0,0.4)";
  // document.getElementById("main").style.marginLeft = "250px";
  document.getElementById("BackgroundOfList").style.width = "100%";
  document.getElementById("BackgroundOfList").style.opacity = "0.8";
  document.getElementById(
    "BackgroundOfList"
  ).style.left = document.getElementById("ListOfProduct").style.width;
  document.getElementById("BackgroundOfList").style.zindex = "1";
}

function CloseList() {
  document.getElementById("ListOfProduct").style.width = "0";
  document.body.style.backgroundColor = "white";
  document.getElementById("BackgroundOfList").style.width = "0";
  document.getElementById("BackgroundOfList").style.opacity = "0";
}

var preScrollpos = window.pageYOffset;
window.onscroll = function () {
  var currentScrollpos = window.pageYOffset;
  if (preScrollpos > currentScrollpos)
    document.getElementById("main-menu").style.top = "0px";
  else document.getElementById("main-menu").style.top = "-200px";
  preScrollpos = currentScrollpos;
};

function FormDangNhap() {
  document.getElementById("FormDangNhap").style.display = "block";
  document.getElementById("FormDangNhap-content").classList.add("animate");
}

function CloseFormDangNhap() {
  document.getElementById("FormDangNhap-content").classList.add("CloseAnimate");
  document.getElementById("FormDangNhap-content").style.transform = "scale(0)";

  document.getElementById("FormDangNhap").style.display = "none";
  document
    .getElementById("FormDangNhap-content")
    .classList.remove("CloseAnimate");
  document.getElementById("FormDangNhap-content").style.transform = "scale(1)";
}

window.onclick = function (event) {
  if (event.target == document.getElementById("FormDangNhap")) {
    CloseFormDangNhap();
  }
};
