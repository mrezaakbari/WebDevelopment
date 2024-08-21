<?php
    /**
     * Deletes a user from the database.
     *
     * @param string $phone_number The phone number of the user to be deleted.
     * @return string A message indicating success or failure.
     */
    function delete_user($phone_number) {
        // Ensure the session is active and the user is an admin
        if (isset($_SESSION['login']) && $_SESSION['login'] === true && isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
            // Connect to the database
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            if ($conn->connect_error) {
                return "Connection failed: " . $conn->connect_error;
            }

            // Prepare the SQL statement to delete the user
            $stmt = $conn->prepare("DELETE FROM users WHERE phone_number = ?");
            $stmt->bind_param("s", $phone_number);

            // Execute the statement and check for errors
            if ($stmt->execute()) {
                $stmt->close();
                $conn->close();
                return "User deleted successfully";
            } else {
                $stmt->close();
                $conn->close();
                return "Error deleting user: " . $stmt->error;
            }
        } else {
            return "Unauthorized access.";
        }
    }

    /**
     * Updates a user's admin status.
     *
     * @param string $phone_number The phone number of the user whose admin status is to be updated.
     * @param bool $is_admin Whether the user should be granted admin privileges (true) or not (false).
     * @return string A message indicating success or failure.
     */
    function update_admin_status($phone_number, $is_admin) {
        // Ensure the session is active and the user is an admin
        if (isset($_SESSION['login']) && $_SESSION['login'] === true && isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
            // Connect to the database
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            if ($conn->connect_error) {
                return "Connection failed: " . $conn->connect_error;
            }

            // Prepare the SQL statement to update the admin status
            $stmt = $conn->prepare("UPDATE users SET admin = ? WHERE phone_number = ?");
            $admin_status = $is_admin ? 1 : 0;
            $stmt->bind_param("is", $admin_status, $phone_number);

            // Execute the statement and check for errors
            if ($stmt->execute()) {
                $stmt->close();
                $conn->close();
                return "Admin status updated successfully";
            } else {
                $stmt->close();
                $conn->close();
                return "Error updating admin status: " . $stmt->error;
            }
        } else {
            return "Unauthorized access.";
        }
    }

    /**
     * Retrieves the details of all users for administrative purposes.
     *
     * @return array An array of associative arrays, each representing a user's details.
     */
    function get_all_user_details() {
        // Ensure the session is active and the user is an admin
        if (isset($_SESSION['login']) && $_SESSION['login'] === true && isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
            // Connect to the database
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            if ($conn->connect_error) {
                return "Connection failed: " . $conn->connect_error;
            }

            // Prepare the SQL statement to retrieve all user details
            $stmt = $conn->prepare("SELECT phone_number, name, last_name, height, weight, blood_type, birth_date, admin FROM users");
            $stmt->execute();
            $result = $stmt->get_result();
            $user_details = [];

            // Fetch the results into an associative array
            while ($row = $result->fetch_assoc()) {
                $user_details[] = $row;
            }

            // Close the statement and connection
            $stmt->close();
            $conn->close();

            // Return the user details
            return $user_details;
        } else {
            return "Unauthorized access.";
        }
    }

    /**
     * Resets the password for a user.
     *
     * @param string $phone_number The phone number of the user whose password is to be reset.
     * @param string $new_password The new password to be set for the user.
     * @return string A message indicating success or failure.
     */
    function reset_user_password($phone_number, $new_password) {
        // Ensure the session is active and the user is an admin
        if (isset($_SESSION['login']) && $_SESSION['login'] === true && isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
            // Connect to the database
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
            if ($conn->connect_error) {
                return "Connection failed: " . $conn->connect_error;
            }

            // Prepare the SQL statement to update the user's password
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE phone_number = ?");
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt->bind_param("ss", $hashed_password, $phone_number);

            // Execute the statement and check for errors
            if ($stmt->execute()) {
                $stmt->close();
                $conn->close();
                return "Password reset successfully";
            } else {
                $stmt->close();
                $conn->close();
                return "Error resetting password: " . $stmt->error;
            }
        } else {
            return "Unauthorized access.";
        }
    }

/**
 * Logs in an admin with the given username and password.
 *
 * @param string $username The admin's username.
 * @param string $password The admin's password.
 * @return string Returns an error message if the login failed, otherwise redirects to the admin dashboard.
 */
function admin_login($username, $password) {
    // Connect to the database
    $pdo = new PDO('mysql:host='.DB_SERVER.';dbname='.DB_NAME, DB_USERNAME, DB_PASSWORD);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Prepare SQL statement to retrieve admin data
    $stmt = $pdo->prepare("SELECT * FROM admins WHERE username=:username LIMIT 1");
    $stmt->bindValue(':username', $username, PDO::PARAM_STR);
    $stmt->execute();

    // Fetch the admin data
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);

    // Verify the password and login if valid
    if ($admin && password_verify($password, $admin['password'])) {
        session_start();
        session_regenerate_id(true);
        $_SESSION['admin_username'] = filter_var($admin['username'], FILTER_SANITIZE_STRING);
        $_SESSION['admin_login'] = true;
        header($GLOBALS['index_page']); // Redirect to the admin dashboard
        exit();
    } else {
        return "Invalid username or password.";
    }
}

/**
 * Retrieves a list of all visits from the database.
 * 
 * @return array An array of associative arrays, each representing a visit.
 */
function get_all_visits() {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL query to select all visits
    $stmt = $conn->prepare("SELECT * FROM visit");
    $stmt->execute();

    // Fetch the results into an associative array
    $result = $stmt->get_result();
    $visit_list = array();
    while ($row = $result->fetch_assoc()) {
        $visit_list[] = $row;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    // Return the list of visits
    return $visit_list;
}

/**
 * Deletes a user from the database based on the provided phone number.
 *
 * @param string $phone_number The phone number of the user to delete.
 * @return string A message indicating whether the deletion was successful or not.
 */
function delete_user($phone_number) {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL statement to delete the user
    $stmt = $conn->prepare("DELETE FROM users WHERE phone_number = ?");
    $stmt->bind_param('s', $phone_number);

    // Execute the statement and check if it was successful
    if ($stmt->execute()) {
        $message = "User deleted successfully.";
    } else {
        $message = "Error deleting user: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    return $message;
}

/**
 * Updates the role of a user in the database.
 *
 * @param string $phone_number The phone number of the user to update.
 * @param string $new_role The new role to assign to the user.
 * @return string A message indicating whether the update was successful or not.
 */
function update_user_role($phone_number, $new_role) {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL statement to update the user role
    $stmt = $conn->prepare("UPDATE users SET role = ? WHERE phone_number = ?");
    $stmt->bind_param('ss', $new_role, $phone_number);

    // Execute the statement and check if it was successful
    if ($stmt->execute()) {
        $message = "User role updated successfully.";
    } else {
        $message = "Error updating user role: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    return $message;
}

/**
 * Retrieves a list of all payments from the database.
 * 
 * @return array An array of associative arrays, each representing a payment.
 */
function get_all_payments() {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL query to select all payments
    $stmt = $conn->prepare("SELECT * FROM payments");
    $stmt->execute();

    // Fetch the results into an associative array
    $result = $stmt->get_result();
    $payment_list = array();
    while ($row = $result->fetch_assoc()) {
        $payment_list[] = $row;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    return $payment_list;
}

/**
 * Deletes a visit record from the database based on the provided visit ID.
 *
 * @param int $visit_id The ID of the visit to delete.
 * @return string A message indicating whether the deletion was successful or not.
 */
function delete_visit($visit_id) {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL statement to delete the visit
    $stmt = $conn->prepare("DELETE FROM visit WHERE id = ?");
    $stmt->bind_param('i', $visit_id);

    // Execute the statement and check if it was successful
    if ($stmt->execute()) {
        $message = "Visit deleted successfully.";
    } else {
        $message = "Error deleting visit: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    return $message;
}

/**
 * Deletes a payment record from the database based on the provided payment ID.
 *
 * @param int $payment_id The ID of the payment to delete.
 * @return string A message indicating whether the deletion was successful or not.
 */
function delete_payment($payment_id) {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Prepare the SQL statement to delete the payment
    $stmt = $conn->prepare("DELETE FROM payments WHERE payment_id = ?");
    $stmt->bind_param('i', $payment_id);

    // Execute the statement and check if it was successful
    if ($stmt->execute()) {
        $message = "Payment deleted successfully.";
    } else {
        $message = "Error deleting payment: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();

    return $message;
}