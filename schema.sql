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
-- Insert the default admin user (email: admin@project2.com, password:password123)
-- The password field contains the Argon2id hash generated from your PHP script.
INSERT INTO Users (firstname, lastname, password, email, role, created_at) VALUES
('Admin', 'User', '$argon2id$v=19$m=65536,t=4,p=3$d05HdVlLODM1MEpuR0d1SA$8fzbKhMjtI+wMQLzfS15UPdLzyINTqml2FN9amuZZnQ', 'admin@project2.com', 'Admin', NOW());