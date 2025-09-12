<?php
// Sample PHP file with vulnerabilities
$userInput = $_GET['input'];

// Vulnerable: SQL Injection
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
mysql_query($query);

// Vulnerable: XSS
echo "<div>" . $userInput . "</div>";

// Vulnerable: Command Injection
system("ls " . $_GET['path']);
?>
