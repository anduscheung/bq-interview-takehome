import fs from "fs";
import csvParser from "csv-parser";
import { format } from "fast-csv";
import path from "path";

const databaseDir = path.join(__dirname, "../database");
const databaseFile = path.join(databaseDir, "database.csv");

export async function readDatabase(): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const results: any[] = [];
    fs.createReadStream(databaseFile) // Path to your CSV file
      .pipe(csvParser())
      .on("data", (row) => {
        results.push(row);
      })
      .on("end", () => {
        resolve(results);
      })
      .on("error", (err) => {
        reject(err);
      });
  });
}

export async function writeDatabase(record: any) {
  const records = await readDatabase(); // Fetch existing records
  records.push(record); // Add the new record

  const writeStream = fs.createWriteStream(databaseFile);
  const csvStream = format({ headers: true });

  csvStream.pipe(writeStream);

  records.forEach((row) => {
    csvStream.write(row);
  });

  csvStream.end();

  return new Promise((resolve, reject) => {
    writeStream.on("finish", () => resolve(true));
    writeStream.on("error", (err) => reject(err));
  });
}
