// change navbar style

window.addEventListener('scroll' , () => {
    document.querySelector('nav').classList.toggele('window-scroll' , window.scrollY > 100)
}) 

//show/hide nav menu
const menu =document.querySelector(".nav_menu");
const menuBtn =document.querySelector("#open-menu-btn");
const closeBtn =document.querySelector("#close-menu-btn");


menuBtn.addEventListener('click' , () => {
    menu.Style.display = "flex";
    closeBtn.style.display = "inline-block";
    menuBtn.style.display = "none";
})

//close nav menu
const closeNav = () => {
    menu.Style.display ="flex";
    closeBtn.style.display = "inline-block";
    menuBtn.style.display = "none";
}

closeBtn.addEventListener("click", closeNav)

