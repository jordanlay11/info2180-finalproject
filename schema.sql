-- Create the main database
CREATE DATABASE IF NOT EXISTS dolphin_crm;

-- Use the newly created database
USE dolphin_crm;

--
-- Table structure for table `Users`
--
CREATE TABLE Users (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, -- auto incrementing integer 
    firstname VARCHAR(255) NOT NULL, -- varchar 
    lastname VARCHAR(255) NOT NULL, -- varchar 
    password VARCHAR(255) NOT NULL, -- varchar, must be hashed 
    email VARCHAR(255) NOT NULL UNIQUE, -- varchar 
    role VARCHAR(50) NOT NULL, -- varchar, either 'Admin' or 'Member' 
    created_at DATETIME NOT NULL -- datetime 
);

--
-- Table structure for table `Contacts`
--
CREATE TABLE Contacts (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, -- auto incrementing integer
    title VARCHAR(255), -- varchar (e.g., Mr, Ms, Dr) 
    firstname VARCHAR(255) NOT NULL, -- varchar 
    lastname VARCHAR(255) NOT NULL, -- varchar 
    email VARCHAR(255) NOT NULL, -- varchar 
    telephone VARCHAR(255), -- varchar 
    company VARCHAR(255), -- varchar 
    type VARCHAR(50) NOT NULL, -- varchar, either 'Sales Lead' or 'Support'
    assigned_to INT NOT NULL, -- integer (store user id) 
    created_by INT NOT NULL, -- integer (store user id)
    created_at DATETIME NOT NULL, -- datetime 
    updated_at DATETIME NOT NULL, -- datetime
    FOREIGN KEY (assigned_to) REFERENCES Users(id),
    FOREIGN KEY (created_by) REFERENCES Users(id)
);

--
-- Table structure for table `Notes`
--
CREATE TABLE Notes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, -- auto incrementing integer
    contact_id INT NOT NULL, -- integer (foreign key to Contacts) 
    comment TEXT NOT NULL, -- text 
    created_by INT NOT NULL, -- integer (store user id) 
    created_at DATETIME NOT NULL, -- datetime 
    FOREIGN KEY (contact_id) REFERENCES Contacts(id),
    FOREIGN KEY (created_by) REFERENCES Users(id)
);


-- Initial Admin User Insertion
-- The password 'password123' must be hashed using a function like PHP's password_hash()
-- The hash below is a placeholder sentence i wrote. it must be replaced with actual, securely generated hash.
INSERT INTO Users (firstname, lastname, password, email, role, created_at) VALUES
('Admin', 'User', 'replace with generated hash from php code before ruinning script', 'admin@project2.com', 'Admin', NOW());