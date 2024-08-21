-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `database`;
USE `database`;

-- Create the `users` table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `phone_number` VARCHAR(15) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `name` VARCHAR(50) NOT NULL,
    `last_name` VARCHAR(50) NOT NULL,
    `height` FLOAT NOT NULL,
    `weight` FLOAT NOT NULL,
    `blood_type` VARCHAR(5) NOT NULL,
    `birth_date` DATE NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create User Activity Log Table
CREATE TABLE user_activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    actor_type ENUM('admin', 'user') NOT NULL,
    activity_description TEXT NOT NULL,
    activity_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create Admins Table
CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Prescriptions Table
CREATE TABLE prescriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    user_id INT NOT NULL,
    prescription_details TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create the `visits` table
CREATE TABLE IF NOT EXISTS `visits` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `phone_number` VARCHAR(15) NOT NULL,
    `visit_type` VARCHAR(50) NOT NULL,
    `visit_date` DATE NOT NULL,
    `title` VARCHAR(100) NOT NULL,
    `detail` TEXT,
    `image` VARCHAR(255),
    `payment_id` INT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`phone_number`) REFERENCES `users`(`phone_number`) ON DELETE CASCADE,
    FOREIGN KEY (`payment_id`) REFERENCES `payments`(`payment_id`) ON DELETE SET NULL
);

-- Create the `payments` table
CREATE TABLE IF NOT EXISTS `payments` (
    `payment_id` INT AUTO_INCREMENT PRIMARY KEY,
    `phone_number` VARCHAR(15) NOT NULL,
    `payment_date` DATE NOT NULL,
    `price` DECIMAL(10, 2) NOT NULL,
    `payment_status` VARCHAR(20) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`phone_number`) REFERENCES `users`(`phone_number`) ON DELETE CASCADE
);

-- Create the `basic_data` table
CREATE TABLE IF NOT EXISTS `basic_data` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `visit_price` DECIMAL(10, 2) NOT NULL,
    `online_max_visit` INT NOT NULL,
    `call_max_visit` INT NOT NULL
);