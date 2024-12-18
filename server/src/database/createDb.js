const fs = require("fs");
const path = require("path");

const databaseFile = path.join(__dirname, "database.csv");

fs.access(databaseFile, fs.constants.F_OK, (err) => {
  if (err) {
    const headers = "encryptedData,encryptedAESKey,iv,signature\n";

    fs.writeFile(databaseFile, headers, (writeErr) => {
      if (writeErr) {
        console.error("Error creating the CSV file:", writeErr);
      } else {
        console.log("CSV file created successfully with headers.");
      }
    });
  } else {
    console.log("CSV file already exists.");
  }
});
