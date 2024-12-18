import React, { useEffect, useState } from "react";
import CryptoJS from "crypto-js";
import {
  importServerPublicKey,
  importClientPrivateKey,
  signData,
  encryptAESKey,
} from "./helpers.ts"; // Keep Web Crypto helpers for RSA
import { CLIENT_PRIVATE_KEY, SERVER_PUBLIC_KEY } from "./keys.constants.ts";

const API_URL = "http://localhost:8080";

function App() {
  const [data, setData] = useState<string>("");
  const [aesKey, setAESKey] = useState<string | null>(null); // AES key as a simple string
  const [serverPublicKey, setServerPublicKey] = useState<CryptoKey | null>(
    null
  );
  const [clientPrivateKey, setClientPrivateKey] = useState<CryptoKey | null>(
    null
  );

  useEffect(() => {
    async function loadKeys() {
      try {
        // Import RSA keys
        const serverPublicKey = await importServerPublicKey(SERVER_PUBLIC_KEY);
        const clientPrivateKey = await importClientPrivateKey(
          CLIENT_PRIVATE_KEY
        );

        // Generate a random 32-character AES key (256 bits)
        const aesKey = CryptoJS.lib.WordArray.random(32).toString(
          CryptoJS.enc.Hex
        );

        setServerPublicKey(serverPublicKey);
        setClientPrivateKey(clientPrivateKey);
        setAESKey(aesKey);

        console.log("AES Key (Hex):", aesKey);
      } catch (error) {
        console.error("Error loading keys:", error);
      }
    }
    loadKeys();
  }, []);

  const encryptPayloadWithAES = (plaintext: string, key: string) => {
    // Generate a random 16-byte IV
    const iv = CryptoJS.lib.WordArray.random(16);

    // Encrypt the data
    const ciphertext = CryptoJS.AES.encrypt(
      plaintext,
      CryptoJS.enc.Hex.parse(key),
      {
        iv: iv,
        mode: CryptoJS.mode.CBC, // Using AES-CBC mode
        padding: CryptoJS.pad.Pkcs7, // Standard padding
      }
    );

    return {
      encryptedData: ciphertext.toString(), // Base64 ciphertext
      iv: iv.toString(CryptoJS.enc.Base64), // Base64 IV for transmission
    };
  };

  const sendData = async () => {
    if (!aesKey || !serverPublicKey || !clientPrivateKey) {
      console.error("Keys not loaded");
      return;
    }

    try {
      // Step 1: Encrypt the data with AES
      const { encryptedData, iv } = encryptPayloadWithAES(data, aesKey);

      // Step 2: Encrypt the AES key with the server's RSA public key
      const encryptedAESKey = await encryptAESKey(
        aesKey, // Pass the AES key directly as a string
        serverPublicKey
      );

      // Step 3: Sign the original data with the client's private key
      const signature = await signData(
        new TextEncoder().encode(data),
        clientPrivateKey
      );

      console.log(">>> before send <<<");
      console.log("Encrypted Data:", encryptedData);
      console.log("IV:", iv);
      console.log("Encrypted AES Key:", encryptedAESKey);
      console.log("Signature:", signature);

      // Step 4: Send data to the server
      await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          encryptedData,
          encryptedAESKey,
          iv,
          signature,
        }),
      });

      console.log("Data sent successfully!");
    } catch (error) {
      console.error("Error sending data:", error);
    }
  };

  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "20px",
        fontSize: "20px",
      }}
    >
      <textarea
        value={data}
        onChange={(e) => setData(e.target.value)}
        placeholder="Enter data"
        style={{ width: "300px", height: "100px", fontSize: "16px" }}
      ></textarea>
      <button
        onClick={sendData}
        style={{ padding: "10px 20px", fontSize: "16px" }}
        disabled={!aesKey || !serverPublicKey || !clientPrivateKey}
      >
        Send Data
      </button>
    </div>
  );
}

export default App;
