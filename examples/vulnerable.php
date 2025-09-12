<?php
// vulnerable.php - Example file with security vulnerabilities for testing

// SQL Injection vulnerability
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
mysql_query($query);

// XSS vulnerability
echo "Hello " . $_GET['name'];

// Path traversal vulnerability
$file = $_GET['file'];
include($file);

// Command injection vulnerability
$cmd = $_POST['command'];
system("ls " . $cmd);

// Hardcoded secrets
$password = "admin123456";
$api_key = "sk-1234567890abcdef1234567890abcdef";

// Weak cryptography
$hash = md5($password);

// More SQL injection patterns
$username = $_POST['username'];
$sql = "SELECT * FROM users WHERE username = '" . $username . "'";
mysqli_query($connection, $sql);

// XSS in different contexts
?>
<script>
var user_data = "<?php echo $_GET['data']; ?>";
</script>

<div id="content">
    <?php echo $_POST['content']; ?>
</div>

<?php
// LDAP injection
$filter = "(&(objectClass=user)(uid=" . $_GET['username'] . "))";
ldap_search($connection, $base_dn, $filter);

// XXE vulnerability
$xml = simplexml_load_string($_POST['xml']);

// Unsafe deserialization
$data = unserialize($_POST['serialized_data']);

// File upload vulnerability
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
?>
