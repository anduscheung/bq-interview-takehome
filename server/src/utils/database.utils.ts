import fs from "fs";
import csvParser from "csv-parser";
import { format } from "fast-csv";
import path from "path";

const databaseDir = path.join(__dirname, "../database");
const databaseFile = path.join(databaseDir, "database.csv");

export interface dbRecord {
  encryptedData: string;
  encryptedAESKey: string;
  iv: string;
  signature: string;
}

export async function readDatabase(): Promise<dbRecord[]> {
  return new Promise((resolve, reject) => {
    const results: any[] = [];
    fs.createReadStream(databaseFile)
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

export async function writeDatabase(record: dbRecord) {
  const fileExists = fs.existsSync(databaseFile);

  const writeStream = fs.createWriteStream(databaseFile, { flags: "a" });

  const csvStream = format({
    headers: !fileExists,
    includeEndRowDelimiter: true,
  });

  csvStream.pipe(writeStream);

  csvStream.write(record);

  csvStream.end();

  return new Promise((resolve, reject) => {
    writeStream.on("finish", () => resolve(true));
    writeStream.on("error", (err) => reject(err));
  });
}
