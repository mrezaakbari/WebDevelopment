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
            log_user_activity($user_id, 'Change Password', 'admin', 'Admin changed user password, User number:'.$phone_number);
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

    /**
     * Retrieves a list of all users from the database.
     *
     * @return array An array of associative arrays, each representing a user.
     */
    function get_all_users() {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select all users
        $stmt = $conn->prepare("SELECT * FROM users");
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
     * Retrieves a list of all admins from the database.
     *
     * @return array An array of associative arrays, each representing an admin.
     */
    function get_all_admins() {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select all admins
        $stmt = $conn->prepare("SELECT * FROM admins");
        $stmt->execute();

        // Fetch the results into an associative array
        $result = $stmt->get_result();
        $admin_list = array();
        while ($row = $result->fetch_assoc()) {
            $admin_list[] = $row;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        // Return the list of admins
        return $admin_list;
    }

    /**
     * Searches for users by name or phone number.
     *
     * @param string $search_query The search term (name or phone number).
     * @return array An array of associative arrays representing users that match the search query.
     */
    function search_user($search_query) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to search for users by name or phone number
        $search_query = '%' . $search_query . '%';
        $stmt = $conn->prepare("SELECT * FROM users WHERE name LIKE ? OR phone_number LIKE ?");
        $stmt->bind_param('ss', $search_query, $search_query);
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
     * Adds a new admin to the database.
     *
     * @param string $username The new admin's username.
     * @param string $password The new admin's password.
     * @return string A message indicating whether the admin was added successfully or not.
     */
    function add_admin($username, $password) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Hash the password before storing it
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare the SQL statement to insert the new admin
        $stmt = $conn->prepare("INSERT INTO admins (username, password) VALUES (?, ?)");
        $stmt->bind_param('ss', $username, $hashed_password);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "New admin added successfully.";
        } else {
            $message = "Error adding new admin: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Removes an admin from the database.
     *
     * @param int $admin_id The ID of the admin to remove.
     * @return string A message indicating whether the admin was removed successfully or not.
     */
    function remove_admin($admin_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to delete the admin
        $stmt = $conn->prepare("DELETE FROM admins WHERE id = ?");
        $stmt->bind_param('i', $admin_id);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "Admin removed successfully.";
        } else {
            $message = "Error removing admin: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Retrieves details of a specific visit by its ID.
     *
     * @param int $visit_id The ID of the visit to retrieve.
     * @return array|null An associative array representing the visit, or null if not found.
     */
    function get_visit_details($visit_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select the visit by ID
        $stmt = $conn->prepare("SELECT * FROM visit WHERE id = ?");
        $stmt->bind_param('i', $visit_id);
        $stmt->execute();

        // Fetch the result into an associative array
        $result = $stmt->get_result();
        $visit_details = $result->fetch_assoc();

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        // Return the visit details
        return $visit_details;
    }

    /**
     * Retrieves details of a specific payment by its ID.
     *
     * @param int $payment_id The ID of the payment to retrieve.
     * @return array|null An associative array representing the payment, or null if not found.
     */
    function get_payment_details($payment_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select the payment by ID
        $stmt = $conn->prepare("SELECT * FROM payments WHERE payment_id = ?");
        $stmt->bind_param('i', $payment_id);
        $stmt->execute();

        // Fetch the result into an associative array
        $result = $stmt->get_result();
        $payment_details = $result->fetch_assoc();

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        // Return the payment details
        return $payment_details;
    }

    /**
     * Updates the details of a specific visit in the database.
     *
     * @param int $visit_id The ID of the visit to update.
     * @param array $new_data An associative array of the new data to update (e.g., ['date' => '2024-08-21', 'description' => 'New Description']).
     * @return string A message indicating whether the update was successful or not.
     */
    function update_visit_details($visit_id, $new_data) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to update the visit details
        $columns = '';
        $values = [];
        foreach ($new_data as $key => $value) {
            $columns .= "$key = ?, ";
            $values[] = $value;
        }
        $columns = rtrim($columns, ', ');
        $values[] = $visit_id;

        $stmt = $conn->prepare("UPDATE visit SET $columns WHERE id = ?");
        $stmt->bind_param(str_repeat('s', count($new_data)) . 'i', ...$values);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "Visit details updated successfully.";
        } else {
            $message = "Error updating visit details: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Updates the details of a specific payment in the database.
     *
     * @param int $payment_id The ID of the payment to update.
     * @param array $new_data An associative array of the new data to update (e.g., ['amount' => 100.00, 'status' => 'Completed']).
     * @return string A message indicating whether the update was successful or not.
     */
    function update_payment_details($payment_id, $new_data) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to update the payment details
        $columns = '';
        $values = [];
        foreach ($new_data as $key => $value) {
            $columns .= "$key = ?, ";
            $values[] = $value;
        }
        $columns = rtrim($columns, ', ');
        $values[] = $payment_id;

        $stmt = $conn->prepare("UPDATE payments SET $columns WHERE payment_id = ?");
        $stmt->bind_param(str_repeat('s', count($new_data)) . 'i', ...$values);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "Payment details updated successfully.";
        } else {
            $message = "Error updating payment details: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Exports the user data to a CSV file.
     *
     * @param string $filename The name of the CSV file to create.
     * @return string A message indicating whether the export was successful or not.
     */
    function export_users_to_csv($filename = 'users_export.csv') {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select all users
        $stmt = $conn->prepare("SELECT * FROM users");
        $stmt->execute();

        // Fetch the results
        $result = $stmt->get_result();

        // Open a file in write mode
        $file = fopen($filename, 'w');

        // Get the headers from the result set and write to the CSV file
        $headers = array_keys($result->fetch_assoc());
        fputcsv($file, $headers);

        // Reset result pointer and write rows to the CSV file
        $result->data_seek(0);
        while ($row = $result->fetch_assoc()) {
            fputcsv($file, $row);
        }

        // Close the file and statement
        fclose($file);
        $stmt->close();
        $conn->close();

        return "Users exported to $filename successfully.";
    }

    /**
     * Sends a notification to users via email or other messaging platform.
     *
     * @param array $user_ids An array of user IDs to send the notification to.
     * @param string $message The message to send.
     * @return string A message indicating whether the notifications were sent successfully or not.
     */
    function send_notification($user_ids, $message) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to select the users by their IDs
        $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
        $stmt = $conn->prepare("SELECT email FROM users WHERE id IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($user_ids)), ...$user_ids);
        $stmt->execute();

        // Fetch the emails
        $result = $stmt->get_result();
        $emails = [];
        while ($row = $result->fetch_assoc()) {
            $emails[] = $row['email'];
        }

        // Send the notification to each email (this is a placeholder for the actual email sending logic)
        foreach ($emails as $email) {
            // mail($email, 'Notification', $message); // Uncomment this line to actually send the email
            // You can use a third-party service like PHPMailer, SendGrid, etc.
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return "Notifications sent successfully.";
    }

    /**
     * Deactivates a user account.
     *
     * @param int $user_id The ID of the user to deactivate.
     * @return string A message indicating whether the account was deactivated successfully or not.
     */
    function deactivate_user_account($user_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to deactivate the user account
        $stmt = $conn->prepare("UPDATE users SET active = 0 WHERE id = ?");
        $stmt->bind_param('i', $user_id);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "User account deactivated successfully.";
        } else {
            $message = "Error deactivating user account: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Reactivates a user account.
     *
     * @param int $user_id The ID of the user to reactivate.
     * @return string A message indicating whether the account was reactivated successfully or not.
     */
    function reactivate_user_account($user_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL statement to reactivate the user account
        $stmt = $conn->prepare("UPDATE users SET active = 1 WHERE id = ?");
        $stmt->bind_param('i', $user_id);

        // Execute the statement and check if it was successful
        if ($stmt->execute()) {
            $message = "User account reactivated successfully.";
        } else {
            $message = "Error reactivating user account: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
    }

    /**
     * Retrieves the activity logs for a specific user.
     *
     * @param int $user_id The ID of the user whose activity logs are being retrieved.
     * @return array An array of associative arrays representing the user's activity logs.
     */
    function get_user_activity_logs($user_id) {
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Prepare the SQL query to select the user's activity logs
        $stmt = $conn->prepare("SELECT * FROM activity_logs WHERE user_id = ?");
        $stmt->bind_param('i', $user_id);
        $stmt->execute();

        // Fetch the results into an associative array
        $result = $stmt->get_result();
        $activity_logs = array();
        while ($row = $result->fetch_assoc()) {
            $activity_logs[] = $row;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        // Return the activity logs
        return $activity_logs;
    }

    /**
     * Allows an admin to write a medical prescription for a user (patient).
     *
     * @param int $admin_id The ID of the admin writing the prescription.
     * @param int $user_id The ID of the user (patient) receiving the prescription.
     * @param string $prescription_details The details of the prescription.
     * @param string $notes Any additional notes regarding the prescription.
     * @return string A message indicating the result of the prescription creation.
     */
    function write_medical_prescription($admin_id, $user_id, $prescription_details, $notes = '') {
        // Connect to the database
        $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Check for connection errors
        if ($conn->connect_error) {
            return "Connection failed: " . $conn->connect_error;
        }

        // Prepare and bind the SQL statement to insert the prescription
        $stmt = $conn->prepare("INSERT INTO prescriptions (admin_id, user_id, prescription_details, notes, created_at) VALUES (?, ?, ?, ?, NOW())");
        $stmt->bind_param('iiss', $admin_id, $user_id, $prescription_details, $notes);

        // Check if the insertion was successful
        if ($stmt->execute()) {
            // Log the activity
            log_user_activity($admin_id, 'Write Prescription', 'admin', "Admin wrote a prescription for user ID: $user_id.");
            $message = "Prescription successfully created.";
        } else {
            $message = "Error writing prescription: " . $stmt->error;
        }

        // Close the statement and connection
        $stmt->close();
        $conn->close();

        return $message;
}

?>