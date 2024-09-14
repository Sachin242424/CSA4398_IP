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
$email = sanitizeInput($_POST['email']);
$password = sanitizeInput($_POST['password']);
$confirmPassword = sanitizeInput($_POST['confirm-password']);

// Check if passwords match
if ($password !== $confirmPassword) {
    die("Passwords do not match.");
}

// Hash the password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// Prepare and bind the SQL statement
$stmt = $conn->prepare("INSERT INTO register (Username, Email, Password, ConfirmPassword) VALUES (?, ?, ?, ?)");
$stmt->bind_param("ssss", $username, $email, $hashedPassword, $hashedPassword);

// Execute the statement
if ($stmt->execute()) {
    echo "Registration successful!";
} else {
    echo "Error: " . $stmt->error;
}

// Close the statement and connection
$stmt->close();
$conn->close();
?>
