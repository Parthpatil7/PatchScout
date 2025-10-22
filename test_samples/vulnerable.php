# Sample vulnerable PHP code for testing PatchScout

<?php
// SQL Injection vulnerability
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($query);

// XSS vulnerability
echo "Welcome " . $_GET['name'];

// Command Injection
$filename = $_GET['file'];
system("cat " . $filename);

// File Inclusion
$page = $_GET['page'];
include($page . '.php');

// Hardcoded credentials
$db_password = "admin123456";
$api_key = "sk-1234567890abcdef";

// Insecure deserialization
$data = unserialize($_POST['data']);

// Weak random for session
$session_id = mt_rand(1000, 9999);
?>
