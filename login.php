<?php
// Database configuration
$server = "localhost";
$username = "root";
$password = "";
$dbname = "project";

// Create a connection
$conn = new mysqli($server, $username, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to sanitize input data
function sanitizeInput($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Validate and sanitize form inputs
$username = sanitizeInput($_POST['username']);
$password = sanitizeInput($_POST['password']);

// Prepare and execute the SQL statement
$stmt = $conn->prepare("SELECT Password FROM register WHERE Username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    // Bind the result to a variable
    $stmt->bind_result($hashedPassword);
    $stmt->fetch();

    // Verify the password
    if (password_verify($password, $hashedPassword)) {
        echo "Login successful!"; // Implement your login logic here
        // Redirect to a protected page, e.g., dashboard.php
        // header("Location: dashboard.php");
        // exit();
    } else {
        echo "Invalid password.";
    }
} else {
    echo "No user found with that username.";
}

// Close the statement and connection
$stmt->close();
$conn->close();
?>
