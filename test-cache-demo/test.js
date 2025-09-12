// JavaScript file with XSS vulnerability
function displayUser(input) {
    document.getElementById("user").innerHTML = input; // XSS vulnerability
}
