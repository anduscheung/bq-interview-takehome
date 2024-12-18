import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import crypto from "crypto";
import {
  SERVER_PRIVATE_KEY,
  CLIENT_PUBLIC_KEY,
} from "./constants/keys.constants";
import { decodeBase64 } from "./utils/crypto.utils";
import { writeDatabase } from "./utils/database.utils";

const PORT = 8080;
const app = express();
app.use(bodyParser.json());

type Database = {
  data: string; // Encrypted data
  encryptedAESKey?: string; // Encrypted AES key (optional initially)
  iv?: string; // IV (optional initially)
  signature?: string; // Digital signature (optional initially)
};
const database: Database = {
  data: "If I dies, all my money gives to Andus. Love you. By Grandma.",
};

app.use(cors());
app.use(express.json());

// Routes
app.get("/", async (req, res) => {
  try {
    const { data: encryptedData, encryptedAESKey, iv, signature } = database;

    if (!encryptedData || !encryptedAESKey || !iv || !signature) {
      return res.status(400).json({ error: "No data found" });
    }

    // Decrypt the AES key using the Server's Private Key
    const decryptedAESKeyBuffer = crypto.privateDecrypt(
      {
        key: SERVER_PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      decodeBase64(encryptedAESKey)
    );

    const aesKey = Buffer.from(decryptedAESKeyBuffer.toString("utf8"), "hex");

    // Validate AES key length
    if (aesKey.length !== 32) {
      throw new Error("Invalid AES key length");
    }

    console.log("Decrypted AES Key Length:", aesKey.length); // Should be 32 bytes

    // Decrypt the payload using the AES key and IV
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      aesKey,
      decodeBase64(iv)
    );

    let decryptedPayload = decipher
      .update(decodeBase64(encryptedData))
      .toString("utf8");
    decryptedPayload += decipher.final("utf8");

    console.log("Decrypted Payload:", decryptedPayload);

    // Validate decrypted payload
    if (
      typeof decryptedPayload !== "string" ||
      decryptedPayload.trim() === ""
    ) {
      throw new Error("Decrypted payload is invalid");
    }

    // Sign the data before sending it back to the client
    const sign = crypto.createSign("sha256");
    sign.update(decryptedPayload);
    sign.end();

    const serverSignature = sign.sign(SERVER_PRIVATE_KEY, "base64");

    console.log("Data Signed with Server Signature:", serverSignature);

    res.json({
      data: decryptedPayload,
      signature: serverSignature,
    });
  } catch (error) {
    if (error instanceof Error) {
      console.error("Decryption failed:", error.message);
      return res.status(400).json({ error: error.message });
    } else {
      console.error("Unknown error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.post("/", async (req, res) => {
  try {
    const { encryptedData, encryptedAESKey, iv, signature } = req.body;

    if (!encryptedData || !encryptedAESKey || !iv || !signature) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    console.log("Received Encrypted Data:", encryptedData);
    console.log("Received IV:", iv);
    console.log("Received Encrypted AES Key:", encryptedAESKey);
    console.log("Received Signature:", signature);

    // Step 1: Decrypt the AES key using the Server's Private Key
    const decryptedAESKeyBuffer = crypto.privateDecrypt(
      {
        key: SERVER_PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      decodeBase64(encryptedAESKey)
    );

    console.log(
      "Decrypted AES Key (Hex):",
      decryptedAESKeyBuffer.toString("utf8")
    );

    // Convert the decrypted AES key from Hex to raw bytes
    const aesKey = Buffer.from(decryptedAESKeyBuffer.toString("utf8"), "hex");
    console.log("AES Key (Raw Buffer):", aesKey);
    console.log("AES Key Length:", aesKey.length);

    // Step 2: Decrypt the payload using the AES key and IV
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc", // AES-CBC mode
      aesKey, // Decrypted AES key
      decodeBase64(iv) // Decoded IV
    );

    let decryptedPayload: string; // Declare as string

    decryptedPayload = decipher
      .update(
        decodeBase64(encryptedData) // Buffer input
      )
      .toString("utf8"); // Convert to string immediately
    decryptedPayload += decipher.final("utf8"); // Concatenate final output

    console.log("Decrypted Payload:", decryptedPayload);

    // Step 3: Verify the signature using the Client's Public Key
    const isVerified = crypto.verify(
      "sha256",
      Buffer.from(decryptedPayload), // Data to verify
      {
        key: CLIENT_PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      decodeBase64(signature) // Signature
    );

    if (!isVerified) {
      console.error("Signature verification failed");
      return res.status(400).json({ error: "Invalid signature" });
    }

    console.log("Signature verified successfully!");

    // Create a new record
    const record = {
      data: encryptedData,
      encryptedAESKey,
      iv,
      signature,
    };

    // Write to CSV
    await writeDatabase(record);

    // Step 4: Respond with success
    return res
      .status(200)
      .json({ message: "Data received and verified", decryptedPayload });
  } catch (error) {
    console.error("Error processing request:", error);
    return res.status(500).json({ error: "Failed to process data" });
  }
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
