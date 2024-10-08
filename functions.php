<?php
    $GLOBALS['index_page']    = "Location: index.php";
    $GLOBALS['visit_page']    = "Location: visit.php";
    $GLOBALS['history_visit'] = "Location: history.php";
    $GLOBALS['user_page']     = "Location: user.php";
    $GLOBALS['payment_page']  = "Location: payment.php";
    $GLOBALS['login_page']    = "Location: login.php";
    $GLOBALS['error_page']    = "Location: error.php";
    $GLOBALS['logout_page']   = "Location: logout.php";

    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'root');
    define('DB_PASSWORD', '');
    define('DB_NAME', 'database');
    define('TABLE_BASIC_DATA', 'basic_data');
    define("MAX_FILE_SIZE", 500000);
    /**
    * Creates a new user account and stores the necessary session data.
    *
    * @param string $phone_number The user's phone number.
    * @param string $password The user's password.
    * @param string $name The user's first name.
    * @param string $last_name The user's last name.
    * @param float  $height The user's height in meters.
    * @param float  $weight The user's weight in kilograms.
    * @param string $blood_type The user's blood type.
    * @param string $birth_date The user's birth date in 'YYYY-MM-DD' format.
    * @return string Returns an error message on failure, otherwise redirects to the home page.
    */
    function create_user($phone_number, $password, $name, $last_name, $height, $weight, $blood_type, $birth_date) {
        try {
            // Validate input data with prepared statement
            $pdo = new PDO("mysql:host=".DB_SERVER.";dbname=".DB_NAME, DB_USERNAME, DB_PASSWORD);
            $stmt = $pdo->prepare("INSERT INTO user (phone_number, password, name, last_name, height, weight, blood_type, birth_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$phone_number, password_hash($password, PASSWORD_DEFAULT), $name, $last_name, $height, $weight, $blood_type, $birth_date]);
            // Store necessary session data
            session_start();
            $_SESSION['phone_number'] = $phone_number;
            $_SESSION['height'] = $height;
            $_SESSION['weight'] = $weight;
            $_SESSION['blood_type'] = $blood_type;
            $_SESSION['birth_date'] = $birth_date;
            $_SESSION['login'] = true;
            // Redirect to home page
            header($GLOBALS['visit_page']);
            exit();
        } catch (PDOException $e) {
            return "Error creating user: " . $e->getMessage();
        }
    }
    function get_user_data($phone_number) {
        if($_SESSION['login']){
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            $stmt = $conn->prepare("SELECT * FROM users WHERE phone_number=?");
            $stmt->bind_param('i', $phone_number);
            $stmt->execute();
            $stmt->bind_result( $name, $last_name, $height, $weight, $blood_type, $birth_date);
            $stmt->fetch();
            $stmt->close();
            $conn->close();
            // Create an array of the retrieved user data
            $user_data = array(
                'phone_number' => $phone_number,
                'name' => $name,
                'last_name' => $last_name,
                'height' => $height,
                'weight' => $weight,
                'blood_type' => $blood_type,
                'birth_date' => $birth_date
            );
            // Return the array of user data
            return $user_data;
        }
        else {
            $url = $GLOBALS['index_page'];
            $https_url = str_replace("http://", "https://", $url);
            header("Location: $https_url");
        }
    }
    function update_user_data($name, $last_name, $height, $weight, $blood_type, $birth_date, $phone_number) {
        // Ensure that the session is started and the user is logged in
        if (isset($_SESSION['login']) && $_SESSION['login'] === true) {
            // Sanitize input data
            $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
            $last_name = htmlspecialchars($last_name, ENT_QUOTES, 'UTF-8');
            $height = filter_var($height, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            $weight = filter_var($weight, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            $blood_type = htmlspecialchars($blood_type, ENT_QUOTES, 'UTF-8');
            $birth_date = htmlspecialchars($birth_date, ENT_QUOTES, 'UTF-8');
            $phone_number = htmlspecialchars($phone_number, ENT_QUOTES, 'UTF-8');
    
            // Update user data in the $_SESSION variable
            $_SESSION['name'] = $name;
            $_SESSION['last_name'] = $last_name;
            $_SESSION['height'] = $height;
            $_SESSION['weight'] = $weight;
            $_SESSION['blood_type'] = $blood_type;
            $_SESSION['birth_date'] = $birth_date;
    
            // Use environment variables for database credentials
            $db_host = getenv('DB_HOST');
            $db_user = getenv('DB_USER');
            $db_pass = getenv('DB_PASS');
            $db_name = getenv('DB_NAME');
    
            // Create a secure connection to the database using MySQLi
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    
            // Check for a connection error
            if ($conn->connect_error) {
                // Handle the error appropriately
                error_log("Connection failed: " . $conn->connect_error);
                exit("Database connection failed. Please try again later.");
            }
    
            // Prepare the SQL statement to prevent SQL injection
            $stmt = $conn->prepare("UPDATE users SET name=?, last_name=?, height=?, weight=?, blood_type=?, birth_date=? WHERE phone_number=?");
            if ($stmt === false) {
                // Handle the error appropriately
                error_log("SQL preparation failed: " . $conn->error);
                exit("Failed to prepare the SQL statement. Please try again later.");
            }
    
            // Bind the parameters with correct types
            $stmt->bind_param('ssssssi', $name, $last_name, $height, $weight, $blood_type, $birth_date, $phone_number);
    
            // Execute the statement and check for errors
            if (!$stmt->execute()) {
                // Handle the error appropriately
                error_log("SQL execution failed: " . $stmt->error);
                exit("Failed to update user data. Please try again later.");
            }
    
            // Close the statement and the connection
            $stmt->close();
            $conn->close();
        } else {
            // Handle unauthorized access attempt
            exit("Unauthorized access.");
        }
    }
    /**
     * Allows a user to change their own password.
     *
     * @param int $user_id The ID of the user changing their password.
     * @param string $old_password The user's current password.
     * @param string $new_password The new password the user wants to set.
     * @param string $confirm_password The confirmation of the new password.
     * @return string A message indicating the result of the password change.
     */
    function change_user_password($user_id, $old_password, $new_password, $confirm_password) {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Check for connection errors
        if ($conn->connect_error) {
            return "Connection failed: " . $conn->connect_error;
        }

        // Fetch the user's current password hash from the database
        $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param('i', $user_id);
        $stmt->execute();
        $stmt->bind_result($stored_password_hash);
        $stmt->fetch();
        $stmt->close();

        // Verify the old password matches the stored password hash
        if (!password_verify($old_password, $stored_password_hash)) {
            return "Old password is incorrect.";
        }

        // Check if the new password and confirm password match
        if ($new_password !== $confirm_password) {
            return "New password and confirmation password do not match.";
        }

        // Hash the new password
        $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);

        // Update the user's password in the database
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->bind_param('si', $new_password_hash, $user_id);

        // Check if the update was successful
        if ($stmt->execute()) {
            // Log the activity
            log_user_activity($user_id, 'Change Password', 'user', 'User changed their own password.');
            $message = "Password changed successfully.";
        } else {
            $message = "Error changing password: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }
    /**
    * Logs in a user with the given phone number and password.
    *
    * @param string $phone_number The user's phone number.
    * @param string $password The user's password.
    * @return string Returns an error message if the login failed, otherwise redirects the user to the home page or dashboard.
    */
    function login($phone_number, $password) {
        // Connect to database with PDO
        $pdo = new PDO('mysql:host='.DB_SERVER.';dbname='.DB_NAME, DB_USERNAME, DB_PASSWORD);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Prepare SQL statement with named parameters
        $stmt = $pdo->prepare("SELECT * FROM users WHERE phone_number=:phone_number LIMIT 1");
        $stmt->bindValue(':phone_number', $phone_number, PDO::PARAM_STR);
        $stmt->execute();
        // Get user data
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if user exists and password is correct
        if ($user && password_verify($password, $user['password'])) {
            // Password is correct, so start a new session
            session_start();
            // Regenerate the session ID to prevent session fixation attacks
            session_regenerate_id(true);
            // Hash the session ID using a secure hashing algorithm
            $session_id = hash('sha256', session_id());
            session_id($session_id);
            // Save user data to session after validating and sanitizing
            $_SESSION['phone_number'] = filter_var($user['phone_number'], FILTER_SANITIZE_STRING);
            $_SESSION['name'] = filter_var($user['name'], FILTER_SANITIZE_STRING);
            $_SESSION['last_name'] = filter_var($user['last_name'], FILTER_SANITIZE_STRING);
            $_SESSION['height'] = filter_var($user['height'], FILTER_VALIDATE_FLOAT);
            $_SESSION['weight'] = filter_var($user['weight'], FILTER_VALIDATE_FLOAT);
            $_SESSION['blood_type'] = filter_var($user['blood_type'], FILTER_SANITIZE_STRING);
            $_SESSION['birth_date'] = filter_var($user['birth_date'], FILTER_SANITIZE_STRING);
            $_SESSION['login'] = true;
            log_user_activity($_SESSION['phone_number'], 'Login', 'User logged in from IP: ' . $_SERVER['REMOTE_ADDR']);
            // Redirect to home page or dashboard using HTTPS
            $url = $GLOBALS['user_page'];
            $https_url = str_replace("http://", "https://", $url);
            header("Location: $https_url");
            exit();
        } else {
            // User not found or password is incorrect
            return "Invalid phone number or password.";
        }
    }
    /**
     * Creates a new visit record in the database.
     *
     * @param int $phoneNumber The phone number of the visitor.
     * @param string $visitType The type of visit (e.g. tour, meeting, event).
     * @param string $visitDate The date of the visit (in YYYY-MM-DD format).
     * @param string $title The title of the visit.
     * @param string $detail Additional details about the visit.
     * @param string|null $image The filename of an image associated with the visit, or null if none.
     * @param int|null $paymentId The ID of the payment associated with the visit, or null if none.
     * @return string A message indicating success or failure.
     */
    function createNewVisit($phoneNumber, $visitType, $visitDate, $title, $detail, $image = null, $paymentId = null) {
        // Connection to database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        if ($conn->connect_error) {
            return "Connection failed: " . $conn->connect_error;
        }
        // Prepare the SQL statement
        $stmt = $conn->prepare("INSERT INTO visit (phone_number, visit_type, visit_date, title, detail, image, payment_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
        // Bind parameters
        $stmt->bind_param("iissssi", $phoneNumber, $visitType, $visitDate, $title, $detail, $image, $paymentId);
        // Execute the statement
        if ($stmt->execute()) {
            $stmt->close();
            $conn->close();
            return "New record created successfully";
        } else {
            $stmt->close();
            $conn->close();
            return "Error creating new record: " . $conn->error;
        }
    }

    // input $_FILES["fileToUpload"]["name"]
    /**
     * Uploads an image to the specified directory with the given file name, after performing
     * various checks to ensure the file is valid and safe to upload.
     *
     * @param array $image An array containing information about the image file to be uploaded.
     *                     The array must contain the following keys: "name", "tmp_name", "size", and "error".
     * @param string $target_dir The directory to which the file should be uploaded.
     * @param array $allowed_types An array of strings representing the file extensions that are allowed to be uploaded.
     *                             Defaults to ["jpg", "jpeg", "png", "gif"] if not specified.
     * @return string A success message indicating that the file was uploaded.
     * @throws InvalidArgumentException if any of the required keys are missing from the $image array.
     * @throws RuntimeException if there is an error with the file upload, or if the file fails any of the checks.
    */
    function upload_image(array $image, string $target_dir = "uploads/", array $allowed_types = ["jpg", "jpeg", "png", "gif"]): string {
        if (!isset($image["name"], $image["tmp_name"], $image["size"], $image["error"])) {
            throw new InvalidArgumentException("Invalid image parameter");
        }
        if ($image["error"] !== UPLOAD_ERR_OK) {
            throw new RuntimeException("Upload error: " . $image["error"]);
        }
        $new_file_name = "my_image_" . $_SESSION['phone_number'] . time() . "." . pathinfo($image["name"], PATHINFO_EXTENSION);
        $target_file = $target_dir . basename($new_file_name);
        $image_type = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
        if (!in_array($image_type, $allowed_types)) {
            throw new RuntimeException("Invalid image type: " . $image_type);
        }
        if ($image["size"] > MAX_FILE_SIZE) {
            throw new RuntimeException("File size exceeds maximum limit: " . MAX_FILE_SIZE);
        }
        $sanitized_file_name = filter_var($new_file_name, FILTER_SANITIZE_STRING);
        $sanitized_file_path = filter_var($target_file, FILTER_SANITIZE_STRING);
        if (file_exists($sanitized_file_path)) {
            throw new RuntimeException("File already exists");
        }
        if (move_uploaded_file($image["tmp_name"], $sanitized_file_path)) {
            return "The file " . htmlspecialchars($sanitized_file_name) . " has been uploaded.";
        } else {
            throw new RuntimeException("Error uploading file");
        }
    }
    /**
    * Creates a new payment record in the database
    *
    * @param string $phone_number The phone number of the user making the payment
    * @param int $payment_id The ID of the payment
    * @param string $payment_date The date of the payment in YYYY-MM-DD format
    * @param float $price The amount of the payment
    * @param string $payment_status The status of the payment (e.g. "pending", "completed", "failed")
    * @throws Exception if there is an error with the database connection or the SQL statement execution
    * @return void
    */
    function create_payment($phone_number, $payment_id, $payment_date, $price, $payment_status){
        // Connection to database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        if ($conn -> connect_error) {
            throw new Exception("Connection failed: " . $conn -> connect_error);
        }
        // Prepare and bind statement
        $stmt = $conn -> prepare("INSERT INTO payments (payment_id, payment_status, payment_date, phone_number, price) VALUES (?, ?, ?, ?, ?)");
        $stmt -> bind_param("iissd", $payment_id, $payment_status, $payment_date, $phone_number, $price);
        // Execute statement
        if ($stmt -> execute()) {
            echo "New record created successfully";
        } else {
            throw new Exception("Error: " . $stmt -> error);
        }
        // Close statement and connection
        $stmt -> close();
        $conn -> close();
    }
    /**
     * Sends a payment request to a specified payment gateway.
     * https://www.zarinpal.com/pg/rest/WebGate/PaymentRequest.json
     * @param string $gateway_url The URL of the payment gateway's API.
     * @param string $merchant_id The merchant ID provided by the payment gateway.
     * @param float $amount The amount to be charged.
     * @param string $description A description of the payment.
     * @param string $callback_url The URL where the payment gateway should send the payment response.
     * @return string The URL of the payment page or an error message.
    */
    function send_payment_request($gateway_url, $merchant_id, $amount, $description = "", $callback_url = "") {
        // Prepare data to be sent to the payment gateway
        $data = array('merchant_id' => $merchant_id, 'amount' => $amount, 'description' => $description, 'callback_url' => $callback_url);
        // Convert data to JSON format
        $json_data = json_encode($data);
        // Send a POST request to the payment gateway with the JSON data
        $ch = curl_init($gateway_url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);
        // Decode the response from the payment gateway
        $response = json_decode($result, true);
        // Check if the request was successful
        if (isset($response['data']['code']) && $response['data']['code'] == 100) {
            // Payment request successful, so return the URL for the payment page
            return $response['data']['payment_url'];
        } else {
            // Payment request failed, so return the error message
            return 'Error: ' . $response['errors']['message'];
        }
    }
    /**
    * Counts the number of visits for a user within a specific date range
    *
    * @param string $phone_number The phone number of the user to count visits for
    * @param string $date The date to count visits for in the format "YYYY-MM-DD"
    * @return int The number of visits for the user and date range
    */
    function count_user_visits($phone_number, $date) {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        // Set the start and end times of the date range
        $start_time = strtotime($date . ' 00:00:00');
        $end_time = strtotime($date . ' 23:59:59');
        // Prepare the SQL query to count the number of visits for the user and date range
        $stmt = $conn->prepare("SELECT COUNT(*) FROM visits WHERE phone_number = ? AND visit_time BETWEEN ? AND ?");
        $stmt->bind_param('iii', $phone_number, $start_time, $end_time);
        $stmt->execute();
        $stmt->bind_result($visit_count);
        $stmt->fetch();
        $stmt->close();
        $conn->close();
        // Return the count of visits for the user and date range
        return $visit_count;
    }
    /**
    * Counts the number of visits for all users within a specified date range.
    * It connects to the database, sets the start and end times of the date range,
    * prepares an SQL query to count the number of visits for all users and the date range,
    * executes the query, fetches the result, and closes the connection.
    * @param string $date The date in the format 'YYYY-MM-DD'.
    * @return int The count of visits for all users within the specified date range.
    */
    function count_all_user_visits($date) {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        // Set the start and end times of the date range
        $start_time = strtotime($date . ' 00:00:00');
        $end_time = strtotime($date . ' 23:59:59');
        // Prepare the SQL query to count the number of visits for all users and date range
        $stmt = $conn->prepare("SELECT COUNT(*) FROM visits WHERE visit_time BETWEEN ? AND ?");
        $stmt->bind_param('ii', $start_time, $end_time);
        $stmt->execute();
        $stmt->bind_result($visit_count);
        $stmt->fetch();
        $stmt->close();
        $conn->close();
        // Return the count of visits for all users and date range
        return $visit_count;
    }
    /**
     * Retrieves a list of all users from the database.
     * It connects to the database, prepares an SQL query to select all users,
     * executes the query, fetches the results, and closes the connection.
     *
     * @return array An array of associative arrays, each representing a user.
    */
    function get_user_list() {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        // Prepare the SQL query to select all users
        $stmt = $conn->prepare("SELECT * FROM users");
        // Execute the query
        $stmt->execute();
        // Fetch the results into an associative array
        $result = $stmt->get_result();
        $user_list = array();
        while ($row = $result->fetch_assoc()) {
            $user_list[] = $row;
        }
        // Close the statement and connection
        $stmt->close();
        $conn->close();
        // Return the list of users
        return $user_list;
    }
    /**
    * Initializes the session variables from the database.
    * It connects to the database, executes a SELECT statement to retrieve the necessary data,
    * sets the session variables accordingly, and closes the connection.
    * @throws Exception if there is an error connecting to the database or executing the SQL statement.
    */
    function Initialization() {
        try {
            // Connect to database
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
            }
            // Prepare and execute SQL statement
            $stmt = $conn->prepare("SELECT visit_price, online_max_visit, call_max_visit FROM " . TABLE_BASIC_DATA);
            $stmt->execute();
            // Fetch results
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $_SESSION['visit_price'] = $row["visit_price"];
                $_SESSION['online_max_visit'] = $row["online_max_visit"];
                $_SESSION['call_max_visit'] = $row["call_max_visit"];
            } else {
                echo "0 results";
            }
            // Close connection and statement
            $stmt->close();
            $conn->close();
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage();
        }
    }
    /**
    * Retrieves a list of all visits for the current day.
    * @return array An array containing information about each visit, including the user ID and visit time.
    */
    function list_today_visits() {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        // Get the current date and set the start and end times of the date range
        $today = date('Y-m-d');
        $start_time = strtotime($today . ' 00:00:00');
        $end_time = strtotime($today . ' 23:59:59');
        // Prepare the SQL query to retrieve visits for the current day
        $stmt = $conn->prepare("SELECT phone_number, visit_time FROM visits WHERE visit_time BETWEEN ? AND ?");
        $stmt->bind_param('ii', $start_time, $end_time);
        $stmt->execute();
        $result = $stmt->get_result();
        // Create an array to store the list of visits
        $visits = array();
        // Fetch results and add them to the array
        while ($row = $result->fetch_assoc()) {
            $phone_number = $row['phone_number'];
            $visit_time = date('Y-m-d H:i:s', $row['visit_time']);
            $visits[] = array('phone_number' => $phone_number, 'visit_time' => $visit_time);
        }
        // Close statement and connection
        $stmt->close();
        $conn->close();
        // Return the list of visits
        return $visits;
    }
    
    /**
     * Logs a user's activity into the activity_logs table.
     *
     * @param int $user_id The ID of the user performing the action.
     * @param string $action A short description of the action (e.g., 'Login', 'Update Profile').
     * @param string|null $details Optional details about the action.
     * @return string A message indicating whether the log was inserted successfully or not.
     */
    function log_user_activity($user_id = $_SESSION['phone_number'], $action, $details = null) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to insert the log
        $stmt = $conn->prepare("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)");
        $stmt->bind_param('iss', $user_id, $action, $details);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "User activity logged successfully.";
        } else {
            $message = "Error logging user activity: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }
    /**
     * Logout function to terminate user session and destroy session data
     *
     * This function terminates the user's session and removes all session data
     * to ensure that the user is fully logged out. It also regenerates the session
     * ID to prevent session fixation attacks, and removes the session cookie to
     * prevent session hijacking attacks.
     *
     * @return void
    */
    function logout() {
        // Unset all of the session variables.
        $_SESSION = array();
        // Regenerate the session ID to prevent session fixation attacks.
        session_regenerate_id(true);
        // If the session was created with a cookie, remove the cookie.
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time()-42000, '/', '', true, true);
        }
        log_user_activity($_SESSION['phone_number'], 'Logout', 'User logged out.');
        // Destroy the session.
        session_destroy();
    }
?>