
C029/401361/2023
GUNTER JAMES

### 
Assignment 1: Developing a Secure Login System
a) Develop a simple login system using HTML,
JavaScript, and PHP/ASP.NET.
b) Implement session-based authentication.
c) Use password hashing and secure cookies for
authentication.
d) Include a feature to prevent SQL Injection attacks.
e) Submit the code with explanations.

### a) Simple Login System

#### HTML (login.html)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login System</title>
</head>
<body>
<h2>Login</h2>
<form id="loginForm" method="POST">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required>
    <br>
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required>
    <br>
    <button type="submit">Login</button>
</form>
</body>
</html>
```

#### PHP (login.php)
```php
<?php
session_start();
require 'database.php'; // Include database connection

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare statement to prevent SQL Injection
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify password
        if (password_verify($password, $hashed_password)) {
            // Set session variables
            $_SESSION['username'] = $username;
            // Set secure cookie
            setcookie("user", $username, time() + (86400 * 30), "/", "", true, true); // 30 days
            header("Location: welcome.php");
            exit();
        } else {
            echo "Invalid password.";
        }
    } else {
        echo "No user found.";
    }
    $stmt->close();
}
?>
```

#### Database Connection (database.php)
```php
<?php
$servername = "localhost";
$username = "root"; // Change as needed
$password = ""; // Change as needed
$dbname = "test"; // Change as needed

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
```

#### Welcome, Page (welcome.php)
```php
<?php
session_start();
if (!isset($_SESSION['username'])) {
    header("Location: login.html");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
</head>
<body>
    <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
    <a href="logout.php">Logout</a>
</body>
</html>
```

#### Logout (logout.php)
```php
<?php
session_start();
session_unset();
session_destroy();
setcookie("user", "", time() - 3600, "/", "", true, true); // Delete cookie
header("Location: login.html");
exit();
?>
```

### b) Session-Based Authentication
- The `session_start()` function is used to initiate a session. User information is stored in the `$_SESSION` superglobal array.
- When the user logs in successfully, their username is stored in the session.

### c) Password Hashing and Secure Cookies
- Passwords are hashed using `password_hash()` when storing them in the database (not shown in the code above, but you should hash passwords when creating users).
- Secure cookies are set with the `setcookie()` function, using the `HttpOnly` and `Secure` flags to prevent JavaScript access and ensure cookies are sent over HTTPS.

### d) Preventing SQL Injection Attacks
- Prepared statements with parameter binding (`$stmt->bind_param()`) are used to prevent SQL injection attacks. This ensures that user input is treated as data, not executable code.

### e) Code Submission
- The code provided above can be saved in respective files (`login.html`, `login.php`, `database.php`, `welcome.php`, `logout.php`) and run on a local server with PHP support (like XAMPP or WAMP).
- Ensure you have a database set up with a `users` table containing `username` and `password` fields, where passwords are stored as hashed values.

