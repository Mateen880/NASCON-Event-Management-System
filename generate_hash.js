// generate_hash.js
const bcrypt = require('bcryptjs');

const plainPassword = '1234qwerty'; // The password you want to hash
const saltRounds = 10;

bcrypt.hash(plainPassword, saltRounds, (err, hashedPassword) => {
  if (err) {
    console.error("Error hashing password:", err);
    return;
  }
  console.log("--- IMPORTANT ---");
  console.log("Plain Password:", plainPassword);
  console.log("Generated Hash:", hashedPassword);
  console.log("--- Copy the 'Generated Hash' value above and use it in the SQL UPDATE statement ---");
});