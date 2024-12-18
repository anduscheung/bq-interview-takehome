import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import {
  prepareDataForClient,
  verifyAndDecryptData,
} from "./utils/crypto.utils";
import { readDatabase, writeDatabase } from "./utils/database.utils";

const PORT = 8080;
const app = express();

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());

app.get("/", async (req, res) => {
  try {
    const databaseEntries = await readDatabase();
    if (!databaseEntries.length) {
      return res.status(404).json({ error: "No data found in the database" });
    }

    let latestEntry = databaseEntries[databaseEntries.length - 1];
    let responsePayload: any = {};
    let fallbackUsed = false;

    try {
      // Try verifying and decrypting the latest data
      const { encryptedData, encryptedAESKey, iv, signature } = latestEntry;
      const decryptedPayload = verifyAndDecryptData({
        encryptedData,
        encryptedAESKey,
        iv,
        signature,
      });
      responsePayload = prepareDataForClient(decryptedPayload);
    } catch (e) {
      // If verification fails, fall back to the second last entry
      console.warn(
        "Latest data corrupted, using fallback to second last entry."
      );
      fallbackUsed = true;

      // Ensure there is a second last entry to fall back on
      const secondLastEntry =
        databaseEntries.length > 1
          ? databaseEntries[databaseEntries.length - 2]
          : null;

      if (secondLastEntry) {
        const { encryptedData, encryptedAESKey, iv, signature } =
          secondLastEntry;
        const decryptedPayload = verifyAndDecryptData({
          encryptedData,
          encryptedAESKey,
          iv,
          signature,
        });

        responsePayload = prepareDataForClient(decryptedPayload);
      } else {
        return res
          .status(400)
          .json({ error: "Corrupted data and no fallback available." });
      }
    }

    // Add a flag to notify the frontend if fallback was used
    res.json({
      fallbackUsed,
      data: responsePayload,
    });
  } catch (error) {
    console.error("Error processing GET request:", error);
    return res.status(500).json({
      error: error instanceof Error ? error.message : "Internal server error",
    });
  }
});

app.post("/", async (req, res) => {
  try {
    const { encryptedData, encryptedAESKey, iv, signature } = req.body;

    if (!encryptedData || !encryptedAESKey || !iv || !signature) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const decryptedPayload = verifyAndDecryptData({
      encryptedData,
      encryptedAESKey,
      iv,
      signature,
    });

    await writeDatabase({
      encryptedData,
      encryptedAESKey,
      iv,
      signature,
    });

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
