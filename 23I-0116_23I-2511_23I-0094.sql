CREATE DATABASE semproject;
USE semproject;

-- -------------------------- DDL Statements--------------------------
CREATE TABLE role (
    RoleID INT AUTO_INCREMENT PRIMARY KEY,
    RoleName ENUM('Admin', 'Event Organizer', 'Participant', 'Sponsor', 'Judge') NOT NULL UNIQUE
);

CREATE TABLE category (
    CategoryID INT AUTO_INCREMENT PRIMARY KEY,
    CategoryName ENUM('Tech Events', 'Business Competitions', 'Gaming Tournaments', 'General Events') NOT NULL Unique
);

CREATE TABLE sponsorship_package (
    PackageID INT AUTO_INCREMENT PRIMARY KEY,
    PackageName ENUM('Title Sponsor', 'Gold Sponsor', 'Silver Sponsor', 'Media Partner') NOT NULL Unique,
    PackageDetails TEXT, 
    PackageCost DECIMAL(10, 2) NOT NULL CHECK (PackageCost >= 0)
);

CREATE TABLE venue (
    Venue_ID INT AUTO_INCREMENT PRIMARY KEY,
    VenueName VARCHAR(100) NOT NULL Unique,
    Location VARCHAR(255),
    Capacity INT CHECK (Capacity > 0),
    Status ENUM('Available', 'Booked', 'Under Maintenance') NOT NULL
);

CREATE TABLE room (
    RoomID INT AUTO_INCREMENT PRIMARY KEY,
    RoomNumber VARCHAR(50) UNIQUE NULL,
    Capacity INT CHECK (Capacity > 0),
    Price DECIMAL(10, 2) CHECK (Price >= 0),
    AvailabilityStatus ENUM('Available', 'Occupied') NOT NULL
);
ALTER TABLE room
MODIFY COLUMN AvailabilityStatus ENUM('Available', 'Occupied') NOT NULL;

-- 3. Add the RoomNumber column
ALTER TABLE room
ADD COLUMN RoomNumber VARCHAR(50) UNIQUE NULL AFTER RoomID;

CREATE TABLE users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    UserName VARCHAR(100) NOT NULL,
    Phone VARCHAR(20),
    Email VARCHAR(100) NOT NULL UNIQUE,
    user_password Varchar(255) Not Null,
    RoleID INT,
    RegistrationTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (RoleID) REFERENCES role(RoleID) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE judge (
    JudgeID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL UNIQUE,
    Expertise VARCHAR(200) NOT NULL,
    FOREIGN KEY (UserID) REFERENCES users(UserID) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE sponsor (
    Sponsor_ID INT AUTO_INCREMENT PRIMARY KEY,
    CompanyName VARCHAR(150) NOT NULL Unique,
    Email VARCHAR(100) UNIQUE,
    PhoneNo VARCHAR(20),
    UserID INT NOT NULL UNIQUE,
    FOREIGN KEY (UserID) REFERENCES users(UserID) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE team (
    TeamID INT AUTO_INCREMENT PRIMARY KEY,
    TeamName VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE judge_role (
    JudgeRoleID INT AUTO_INCREMENT PRIMARY KEY,
    JudgeRole ENUM('Head Judge', 'Assistant Judge', 'Panel Member') NOT NULL UNIQUE
);

CREATE TABLE participant (
    Participant_ID INT AUTO_INCREMENT PRIMARY KEY,
    University VARCHAR(150),
    TeamID INT NULL, 
    UserID INT NOT NULL UNIQUE,
    FOREIGN KEY (UserID) REFERENCES users(UserID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (TeamID) REFERENCES team(TeamID) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE event (
    Event_ID INT AUTO_INCREMENT PRIMARY KEY,
    EventName VARCHAR(150) NOT NULL,
    EventDescription TEXT, 
    Rules TEXT,
    MaxParticipants INT check (MaxParticipants > 0),
    EventDateTime DATETIME not null,
    RegistrationFee DECIMAL(10,2) check (RegistrationFee >= 0),
    CategoryID INT,
    CreatedTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (CategoryID) REFERENCES category(CategoryID) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE sponsorship_contracts (
    ContractID INT AUTO_INCREMENT PRIMARY KEY,
    ContractDate DATE NOT NULL,
    ContractStatus ENUM('Signed', 'Pending', 'Expired') NOT NULL,
    PaymentStatus ENUM('Paid', 'Pending', 'Overdue') NOT NULL,
    SponsorID INT NOT NULL,
    PackageID INT NOT NULL,
    FOREIGN KEY (SponsorID) REFERENCES sponsor(Sponsor_ID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (PackageID) REFERENCES sponsorship_package(PackageID) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE registration (
    RegistrationID INT AUTO_INCREMENT PRIMARY KEY,
    EventID INT NOT NULL,
    TeamID INT NULL,
    ParticipantID INT NULL,
    RegistrationTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PaymentStatus ENUM('Paid', 'Pending') NOT NULL DEFAULT 'Pending',
    FOREIGN KEY (EventID) REFERENCES event(Event_ID) ON DELETE CASCADE ON UPDATE CASCADE, 
    FOREIGN KEY (TeamID) REFERENCES team(TeamID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (ParticipantID) REFERENCES participant(Participant_ID) ON DELETE CASCADE ON UPDATE CASCADE
);

select* from registration;

CREATE TABLE event_round (
    RoundID INT AUTO_INCREMENT PRIMARY KEY,
    RoundName ENUM('Prelims', 'Semi-Finals', 'Finals') NOT NULL,
    EventID INT NOT NULL,
    FOREIGN KEY (EventID) REFERENCES event(Event_ID) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT uc_event_round UNIQUE (EventID, RoundName)
);

CREATE TABLE event_judge (
    EventID INT NOT NULL,
    JudgeID INT NOT NULL,
    JudgeRoleID INT NOT NULL,
    PRIMARY KEY (EventID, JudgeID),
    FOREIGN KEY (EventID) REFERENCES event(Event_ID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (JudgeID) REFERENCES judge(JudgeID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (JudgeRoleID) REFERENCES judge_role(JudgeRoleID) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE accommodation (
    AccommodationID INT AUTO_INCREMENT PRIMARY KEY,
    AccommodationStatus ENUM('Requested', 'Allocated', 'Cancelled') NOT NULL,
    NumberOfPeople INT not null CHECK (NumberOfPeople > 0),
    Budget DECIMAL(10, 2) not null,
    RegistrationID INT NOT NULL UNIQUE, 
    FOREIGN KEY (RegistrationID) REFERENCES registration(RegistrationID) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE payment (
    Payment_ID INT AUTO_INCREMENT PRIMARY KEY,
    Amount DECIMAL(10, 2) NOT NULL CHECK (Amount > 0),
    PaymentDate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PaymentType ENUM('Online', 'Manual') NOT NULL,
    RegistrationID INT NULL,
    ContractID INT NULL,
    FOREIGN KEY (RegistrationID) REFERENCES registration(RegistrationID) ON DELETE set null ON UPDATE CASCADE,
    FOREIGN KEY (ContractID) REFERENCES sponsorship_contracts(ContractID) ON DELETE set null ON UPDATE CASCADE
);
SHOW CREATE TABLE room;

ALTER TABLE payment
DROP FOREIGN KEY payment_ibfk_1;

ALTER TABLE payment
DROP FOREIGN KEY payment_ibfk_2;
-- Add the foreign key for RegistrationID with ON DELETE CASCADE
ALTER TABLE payment
ADD CONSTRAINT fk_payment_registration -- Giving it an explicit name now
FOREIGN KEY (RegistrationID) REFERENCES registration(RegistrationID)
ON DELETE CASCADE -- Set the desired action
ON UPDATE CASCADE; -- Keep the existing update action

-- Add the foreign key for ContractID with ON DELETE CASCADE
ALTER TABLE payment
ADD CONSTRAINT fk_payment_contract -- Giving it an explicit name now
FOREIGN KEY (ContractID) REFERENCES sponsorship_contracts(ContractID)
ON DELETE CASCADE -- Set the desired action
ON UPDATE CASCADE;

CREATE TABLE venue_schedule (
    ScheduleID INT AUTO_INCREMENT PRIMARY KEY,
    ScheduleDate DATE NOT NULL,
    StartTime TIME NOT NULL,
    EndTime TIME NOT NULL,
    VenueID INT NOT NULL,
    Event_RoundID INT NOT NULL,
    FOREIGN KEY (VenueID) REFERENCES venue(Venue_ID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (Event_RoundID) REFERENCES event_round(RoundID) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_event_times CHECK (EndTime > StartTime),
    UNIQUE KEY venue_time_slot (VenueID, ScheduleDate, StartTime)
);

CREATE TABLE evaluations (
    EvaluationID INT AUTO_INCREMENT PRIMARY KEY,
    Comments TEXT,
    Score DECIMAL(5,2) NOT NULL CHECK (Score >= 0),
    EventJudgeID_Event INT NOT NULL,
    EventJudgeID_Judge INT NOT NULL,
    RegistrationID INT NOT NULL,
    RoundID INT NOT NULL,
    EvaluationTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (EventJudgeID_Event, EventJudgeID_Judge) REFERENCES event_judge(EventID, JudgeID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (RegistrationID) REFERENCES registration(RegistrationID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (RoundID) REFERENCES event_round(RoundID) ON DELETE CASCADE ON UPDATE CASCADE,
	UNIQUE KEY unique_evaluation (EventJudgeID_Event, EventJudgeID_Judge, RegistrationID, RoundID)
);

CREATE TABLE room_allocation (
    AllocationID INT AUTO_INCREMENT PRIMARY KEY,
    CheckInDate DATE NOT NULL,
    CheckOutDate DATE NOT NULL,
    RoomID INT NOT NULL,
    AccommodationID INT NOT NULL Unique, 
    AllocationTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (RoomID) REFERENCES room(RoomID) ON DELETE RESTRICT ON UPDATE CASCADE, 
    FOREIGN KEY (AccommodationID) REFERENCES accommodation(AccommodationID) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_dates CHECK (CheckOutDate > CheckInDate)
);

CREATE TABLE role_requests (
    RequestID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    RequestedRole ENUM('Event Organizer', 'Judge', 'Sponsor') NOT NULL,
    Details TEXT,
    Status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
    RequestTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES users(UserID) ON DELETE CASCADE ON UPDATE CASCADE
);

DROP TABLE IF EXISTS checkin;
CREATE TABLE checkin (
    CheckinID INT PRIMARY KEY AUTO_INCREMENT,
    AllocationID INT NOT NULL,
    ActualCheckinDate DATETIME NOT NULL,
    ActualCheckoutDate DATETIME NULL,
    Status ENUM('Reserved', 'Checked In', 'Checked Out') DEFAULT 'Reserved',
    Notes TEXT NULL,
    FOREIGN KEY (AllocationID) REFERENCES room_allocation(AllocationID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sponsorship_requests (
    RequestID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    PackageID INT NOT NULL,
    CompanyName VARCHAR(150) NOT NULL,
    CompanyEmail VARCHAR(100) NOT NULL,
    CompanyPhone VARCHAR(20),
    Details TEXT,
    Status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
    RequestTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES users(UserID) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (PackageID) REFERENCES sponsorship_package(PackageID) ON DELETE RESTRICT ON UPDATE CASCADE
);

-- Add index for faster lookups
CREATE INDEX idx_sponsorship_requests_user ON sponsorship_requests(UserID);
CREATE INDEX idx_sponsorship_requests_package ON sponsorship_requests(PackageID);
CREATE INDEX idx_sponsorship_requests_status ON sponsorship_requests(Status); 
-- ---------------------------Indexes---------------------------------
-- For User Login
CREATE INDEX idx_user_email ON users(Email);
-- For Filtering/Sorting Events
CREATE INDEX idx_event_datetime ON event(EventDateTime);
CREATE INDEX idx_event_category ON event(CategoryID);
-- For Finding Registrations 
CREATE INDEX idx_registration_event ON registration(EventID);
CREATE INDEX idx_registration_participant ON registration(ParticipantID);
CREATE INDEX idx_registration_team ON registration(TeamID);
CREATE INDEX idx_registration_payment_status ON registration(PaymentStatus);
-- For Finding Payments
CREATE INDEX idx_payment_registration ON payment(RegistrationID);
CREATE INDEX idx_payment_contract ON payment(ContractID);
-- For Finding Schedule Slots for a specific Event/Round
CREATE INDEX idx_schedule_event_round ON venue_schedule(Event_RoundID);
-- For Finding Room Allocations for a specific room
CREATE INDEX idx_room_allocation_room ON room_allocation(RoomID);
-- For Finding Contracts for a Sponsor
CREATE INDEX idx_contracts_sponsor ON sponsorship_contracts(SponsorID);
-- For Finding Participants on a team
CREATE INDEX idx_participant_team ON participant(TeamID);
CREATE INDEX idx_checkin_allocation ON checkin(AllocationID);
-- ---------Inserting the data-------------------
INSERT INTO category (CategoryName) 
VALUES 
('Tech Events'), 
('Business Competitions'), 
('Gaming Tournaments'), 
('General Events');


INSERT INTO event (EventName, EventDescription, Rules, MaxParticipants, EventDateTime, RegistrationFee, CategoryID)
VALUES 
('AI Innovation Challenge', 'A competition focused on artificial intelligence and innovative solutions.', '1. Maximum of 3 participants per team. 2. No plagiarism of ideas.', 50, '2025-06-10 10:00:00', 150.00, 1),
('Business Pitching Contest', 'A contest where participants pitch their business ideas to investors.', '1. 5-minute pitch. 2. Presentation slides required.', 30, '2025-06-12 09:00:00', 100.00, 2),
('Esports Tournament', 'Competitive gaming tournament for various games like DOTA 2 and League of Legends.', '1. Teams of 5 players. 2. No cheating or using third-party software.', 20, '2025-06-15 12:00:00', 200.00, 3),
('Hackathon for Startups', 'A 48-hour coding competition to create tech solutions for startups.', '1. Teams of up to 4 members. 2. All code must be written during the event.', 40, '2025-06-18 14:00:00', 75.00, 1);

select* from event;

INSERT INTO sponsorship_package (PackageName, PackageDetails, PackageCost) VALUES
('Title Sponsor', 'Top-tier sponsor. Exclusive branding across all event materials, VIP lounge access, main stage mention.', 10000.00),
('Gold Sponsor', 'Premium branding across major event areas, priority booth placement, mentions in press releases.', 7000.00),
('Silver Sponsor', 'Significant branding across selected event areas, booth space, mentions in newsletters.', 4000.00),
('Media Partner', 'Branding on media walls and online promotions. Coverage rights and interviews.', 2000.00);

INSERT INTO role (RoleName) 
VALUES 
('Admin'), 
('Event Organizer'), 
('Participant'), 
('Sponsor'), 
('Judge');

select* from role;

INSERT INTO users (UserName, Phone, Email, user_password, RoleID)
VALUES('Hasaan','03331234567','i230094@isb.nu.edu.pk','$2b$10$8RCpxaNezD.ygWONqeUWpul7DQXAU.WkJm0XcRprR2z9J7/3Zdesq',1);

select* from users;
-- Make sure to replace the placeholder with the actual hash generated by the script
UPDATE users
SET user_password = '$2b$10$8RCpxaNezD.ygWONqeUWpul7DQXAU.WkJm0XcRprR2z9J7/3Zdesq'
WHERE Email = 'i230094@isb.nu.edu.pk';

INSERT INTO venue (VenueName, Location, Capacity, Status) VALUES 
('Margalah-1', 'C Block', 35, 'Available'),
('Margalah-2', 'C Block', 40, 'Available'),
('Margalah-3', 'C Block', 30, 'Available'),
('Margalah-4', 'C Block', 35, 'Available'),
('Rawal-1', 'C Block', 40, 'Available'),
('Rawal-2', 'C Block', 38, 'Available'),
('Rawal-3', 'B Block', 32, 'Available'),
('Rawal-4', 'B Block', 35, 'Available'),
('GPU Lab', 'B Block', 30, 'Available'),
('Karakoram-1', 'A Block', 40, 'Available'),
('Karakoram-2', 'A Block', 38, 'Available'),
('Karakoram-3', 'A Block', 35, 'Available'),
('Mehran-1', 'A Block', 32, 'Available'),
('Mehran-2', 'A Block', 30, 'Available'),
('Mehran-3', 'A Block', 35, 'Available');

INSERT INTO room (RoomNumber, Capacity, Price, AvailabilityStatus) VALUES
-- Block A - Price 700.00
('A-101', 5, 700.00, 'Available'),
('A-102', 5, 700.00, 'Available'),
('A-103', 5, 700.00, 'Available'),
('A-104', 5, 700.00, 'Available'),
('A-105', 5, 700.00, 'Available'),
('A-201', 5, 700.00, 'Available'),
('A-202', 5, 700.00, 'Available'),
('A-203', 5, 700.00, 'Available'),
('A-204', 5, 700.00, 'Available'),
('A-205', 5, 700.00, 'Available'),
-- Block B - Price 500.00
('B-101', 5, 500.00, 'Available'),
('B-102', 5, 500.00, 'Available'),
('B-103', 5, 500.00, 'Available'),
('B-104', 5, 500.00, 'Available'),
('B-105', 5, 500.00, 'Available'),
('B-201', 5, 500.00, 'Available'),
('B-202', 5, 500.00, 'Available'),
('B-203', 5, 500.00, 'Available'),
('B-204', 5, 500.00, 'Available'),
('B-205', 5, 500.00, 'Available'),
-- Block C - Price 1000.00
('C-101', 5, 1000.00, 'Available'),
('C-102', 5, 1000.00, 'Available'),
('C-103', 5, 1000.00, 'Available'),
('C-104', 5, 1000.00, 'Available'),
('C-105', 5, 1000.00, 'Available'),
('C-201', 5, 1000.00, 'Available'),
('C-202', 5, 1000.00, 'Available'),
('C-203', 5, 1000.00, 'Available'),
('C-204', 5, 1000.00, 'Available'),
('C-205', 5, 1000.00, 'Available');

-- Views
CREATE VIEW vw_event_participants AS
SELECT 
    e.EventName,
    p.Participant_ID,
    u.UserName,
    p.University,
    r.RegistrationTimestamp
FROM event e
JOIN registration r ON e.Event_ID = r.EventID
JOIN participant p ON r.ParticipantID = p.Participant_ID
JOIN users u ON p.UserID = u.UserID;

CREATE VIEW vw_sponsorship_summary AS
SELECT 
    s.CompanyName,
    sp.PackageName,
    sp.PackageCost,
    sc.ContractStatus,
    p.Amount AS PaymentAmount,
    p.PaymentDate
FROM sponsor s
JOIN sponsorship_contracts sc ON s.Sponsor_ID = sc.SponsorID
JOIN sponsorship_package sp ON sc.PackageID = sp.PackageID
LEFT JOIN payment p ON sc.ContractID = p.ContractID;

CREATE VIEW vw_venue_schedule_conflicts AS
SELECT 
    v1.ScheduleID,
    v1.ScheduleDate,
    v1.StartTime,
    v1.EndTime,
    e1.EventName AS Event1,
    e2.EventName AS Event2
FROM venue_schedule v1
JOIN venue_schedule v2 ON v1.VenueID = v2.VenueID
    AND v1.ScheduleDate = v2.ScheduleDate
    AND v1.ScheduleID < v2.ScheduleID
    AND (
        (v1.StartTime BETWEEN v2.StartTime AND v2.EndTime)
        OR (v1.EndTime BETWEEN v2.StartTime AND v2.EndTime)
    )
JOIN event_round er1 ON v1.Event_RoundID = er1.RoundID
JOIN event_round er2 ON v2.Event_RoundID = er2.RoundID
JOIN event e1 ON er1.EventID = e1.Event_ID
JOIN event e2 ON er2.EventID = e2.Event_ID;

-- Indexes
CREATE INDEX idx_event_name ON event(EventName);
CREATE INDEX idx_participant_university ON participant(University);
CREATE INDEX idx_sponsor_company ON sponsor(CompanyName);
CREATE INDEX idx_venue_schedule ON venue_schedule(VenueID, ScheduleDate);
CREATE INDEX idx_payment_date ON payment(PaymentDate);

-- Stored Procedures
DELIMITER $$

-- Then run this simplified procedure definition:
CREATE PROCEDURE sp_create_event_rounds (
    IN p_event_id INT,
    IN p_round_count INT
)
BEGIN
    -- Declare only the loop counter
    DECLARE i INT;

    -- Initialize counter
    SET i = 1;

    -- Loop to insert rounds
    WHILE i <= p_round_count DO
        INSERT INTO event_round (EventID, RoundName)
        VALUES (
            p_event_id,
            -- Determine round name based on counter
            CASE
                WHEN i = 1 THEN 'Prelims'
                WHEN i = 2 THEN 'Semi-Finals'
                WHEN i = 3 THEN 'Finals'
                ELSE CONCAT('Round ', i) -- For rounds beyond the standard 3
            END
        );

        -- Increment counter
        SET i = i + 1;
    END WHILE;

END$$

-- Finally, run this command:
DELIMITER ;
DELIMITER //

CREATE PROCEDURE sp_calculate_event_statistics(
    IN p_event_id INT,
    OUT p_total_participants INT,
    OUT p_total_revenue DECIMAL(10,2),
    OUT p_average_score DECIMAL(5,2)
)
BEGIN
    -- Calculate total distinct participants for the event
    SELECT COUNT(DISTINCT r.ParticipantID) INTO p_total_participants
    FROM registration r
    WHERE r.EventID = p_event_id;

    -- Calculate total revenue from payments linked to the event's registrations
    SELECT COALESCE(SUM(p.Amount), 0) INTO p_total_revenue
    FROM payment p
    JOIN registration r ON p.RegistrationID = r.RegistrationID
    WHERE r.EventID = p_event_id;

    -- Calculate average score from evaluations linked to the event's rounds
    SELECT COALESCE(AVG(e.Score), 0) INTO p_average_score
    FROM evaluations e
    JOIN event_round er ON e.RoundID = er.RoundID
    WHERE er.EventID = p_event_id;
END //

DELIMITER ;

-- Triggers
DELIMITER //

CREATE TRIGGER tr_payment_status_update
AFTER INSERT ON payment
FOR EACH ROW
BEGIN
    -- Update registration status if payment is linked
    IF NEW.RegistrationID IS NOT NULL AND NEW.Amount > 0 THEN
        UPDATE registration
        SET PaymentStatus = 'Paid'
        WHERE RegistrationID = NEW.RegistrationID;
    END IF;
    -- Update contract status if payment is linked
    IF NEW.ContractID IS NOT NULL AND NEW.Amount > 0 THEN
        UPDATE sponsorship_contracts
        SET PaymentStatus = 'Paid'
        WHERE ContractID = NEW.ContractID;
    END IF;
END //

DELIMITER ;

DELIMITER //

CREATE TRIGGER tr_event_registration_check
BEFORE INSERT ON registration
FOR EACH ROW
BEGIN
    DECLARE max_participants INT;
    DECLARE current_participants INT;

    -- Get the maximum participants allowed for the event
    SELECT MaxParticipants INTO max_participants
    FROM event
    WHERE Event_ID = NEW.EventID;

    -- Get the current number of participants registered for the event
    SELECT COUNT(*) INTO current_participants
    FROM registration
    WHERE EventID = NEW.EventID;

    -- Check if the event is full
    IF current_participants >= max_participants THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Event has reached maximum participants';
    END IF;
END //

DELIMITER ;

-- Events (Database Scheduler)
DELIMITER //

CREATE EVENT ev_send_event_reminders
ON SCHEDULE EVERY 1 DAY -- Starts running daily after creation (if scheduler enabled)
DO
BEGIN
    -- Temporary table to hold notifications to be potentially processed
    -- Ensure the user running the event scheduler has permission to create temp tables
    CREATE TEMPORARY TABLE IF NOT EXISTS temp_notifications (
        UserID INT,
        Message TEXT,
        NotificationDate DATE
    );

    -- Populate temp table with reminder messages for participants in events starting tomorrow
    INSERT INTO temp_notifications (UserID, Message, NotificationDate)
    SELECT
        p.UserID,
        CONCAT('Reminder: Event "', e.EventName, '" starts tomorrow at ', DATE_FORMAT(e.EventDateTime, '%Y-%m-%d %H:%i')),
        CURDATE()
    FROM registration r
    JOIN participant p ON r.ParticipantID = p.Participant_ID
    JOIN event e ON r.EventID = e.Event_ID
    WHERE DATE(e.EventDateTime) = DATE_ADD(CURDATE(), INTERVAL 1 DAY); -- Check if event date is exactly tomorrow

    -- >>> Add application-specific logic here <<<
    -- For example, insert into a persistent 'notifications' table,
    -- or log these messages for an external process to handle.
    -- INSERT INTO notifications (UserID, Message, IsRead, CreatedAt)
    -- SELECT UserID, Message, 0, NOW() FROM temp_notifications;

    -- Clean up the temporary table
    DROP TEMPORARY TABLE IF EXISTS temp_notifications;
END //

DELIMITER ;

-- basic queries
select* from role_requests;
select* from users;
select* from participant;
select* from registration;
select* from team;
select* from sponsor;
select* from payment;
select* from sponsorship_contracts;
select* from sponsorship_requests;
select* from event;
select* from event_round;
select* from venue;
select* from venue_schedule;
select* from room;
select* from accommodation;
select* from role;