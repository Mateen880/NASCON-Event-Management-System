-- Ensure we have the sponsorship_requests table
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

-- Add index for faster lookups if not already created
CREATE INDEX IF NOT EXISTS idx_sponsorship_requests_user ON sponsorship_requests(UserID);
CREATE INDEX IF NOT EXISTS idx_sponsorship_requests_package ON sponsorship_requests(PackageID);
CREATE INDEX IF NOT EXISTS idx_sponsorship_requests_status ON sponsorship_requests(Status); 