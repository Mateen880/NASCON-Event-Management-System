# NASCON-Event-Management-System
# 🎪 NASCON Event Management System – Web-Based MySQL Project

An end-to-end event management system designed for **NASCON**, our university’s flagship tech and talent convention. The system automates and streamlines core workflows such as registration, event scheduling, sponsorship, accommodation, and payment management using a robust **MySQL database** and a custom-built **Node.js backend**.

---

## 🚀 Core Modules

### 👤 User Management  
- Role-based access control for Admins, Organizers, Judges, Participants, and Sponsors  
- User roles implemented using **DCL (GRANT / REVOKE)**  

### 📅 Event & Venue Scheduling  
- Tech, Business, Gaming, and General events management  
- Venue booking with conflict checks using SQL constraints  
- Multi-round event support (Prelims, Semis, Finals)

### 💼 Sponsorship Handling  
- Title, Gold, Silver sponsors, and Media Partners  
- Contract tracking, payment monitoring, and branding reports  

### 🏨 Accommodation Assignment  
- Auto-allocation based on budget, availability, and team size  
- Generates clean room assignment reports  

### 💳 Payment & Finance  
- Registration and sponsorship payments (manual + online)  
- Financial reports: revenue, sponsorship funds, and accommodation charges  

### 🏆 Judges & Scoring  
- Judge allocation per event  
- Participant scoring and winner announcement  
- Leaderboard generation using SQL AVG and sorting  

### 📊 Reports & Analytics  
- Participant stats and demographics  
- Venue utilization reports  
- Sponsorship and revenue summaries  

---

## 🛠️ Technologies Used

- **Node.js**, **Express.js** – for backend server  
- **MySQL** – for relational data storage  
- **bcryptjs**, **express-session** – for authentication  
- **JavaScript**, **HTML/CSS** – for UI and dashboard  
- **Stored Procedures**, **Triggers**, **Joins**, **Views** – for efficient database logic  

---

## 🧠 Database Concepts Practiced

- ✅ DDL, DML, and DCL SQL statements  
- ✅ Inner & Left Joins for multi-table reports  
- ✅ Aggregate functions: `SUM`, `AVG`, `HAVING`  
- ✅ Views, Indexes, and Stored Procedures  
- ✅ Triggers for automated status updates  
- ✅ Event Scheduler for reminders  
- ✅ Role-based access via SQL GRANT/REVOKE  

---


