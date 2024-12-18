import React, { useEffect, useState, useRef } from "react";
import {
  encryptData,
  loadKeysAndGenerateAES,
  decryptAndVerifyData,
} from "./utils/crypto.utils.ts";

const API_URL = "http://localhost:8080";

function App() {
  const [data, setData] = useState<string>("");

  const aesKeyRef = useRef<string | null>(null);
  const serverPublicKeyForEncryptRef = useRef<CryptoKey | null>(null);
  const serverPublicKeyForVerifyRef = useRef<CryptoKey | null>(null);
  const clientPrivateKeyForSigningRef = useRef<CryptoKey | null>(null);
  const clientPrivateKeyForDecryptRef = useRef<CryptoKey | null>(null);

  useEffect(() => {
    async function loadKeys() {
      try {
        const {
          serverPublicKeyForEncrypt,
          serverPublicKeyForVerify,
          clientPrivateKeyForSigning,
          clientPrivateKeyForDecrypt,
          aesKey,
        } = await loadKeysAndGenerateAES();

        serverPublicKeyForEncryptRef.current = serverPublicKeyForEncrypt;
        clientPrivateKeyForSigningRef.current = clientPrivateKeyForSigning;
        clientPrivateKeyForDecryptRef.current = clientPrivateKeyForDecrypt;
        serverPublicKeyForVerifyRef.current = serverPublicKeyForVerify;
        aesKeyRef.current = aesKey;
      } catch (error) {
        console.error("Error loading keys:", error);
      }
    }

    loadKeys();
  }, []);

  const sendData = async () => {
    if (
      !aesKeyRef.current ||
      !serverPublicKeyForEncryptRef.current ||
      !clientPrivateKeyForSigningRef.current
    ) {
      alert("Keys are not loaded, try again after 1 second");
      return;
    }

    try {
      const preparedData = await encryptData(
        data,
        aesKeyRef.current,
        serverPublicKeyForEncryptRef.current,
        clientPrivateKeyForSigningRef.current
      );

      await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(preparedData),
      });
      alert("Data sent successfully!");
    } catch (error) {
      console.error("Error sending data:", error);
    }
  };

  const fetchAndVerifyData = async () => {
    try {
      if (
        !serverPublicKeyForVerifyRef.current ||
        !clientPrivateKeyForDecryptRef.current
      ) {
        alert("Keys are not loaded, try again after 1 second");
        return;
      }

      const response = await fetch(API_URL);

      if (response.status === 404) {
        alert("No data found");
        return;
      }

      if (response.status === 400) {
        alert(
          "Data may have been tampered with and no previous data available as fallback"
        );
        return;
      }

      if (!response.ok) {
        alert("Data is corrupted or tempered, please contact support");
        return;
      }

      const {
        fallbackUsed,
        data: { encryptedData, encryptedAESKey, iv, signature },
      } = await response.json();

      const decryptedPayload = await decryptAndVerifyData(
        encryptedData,
        encryptedAESKey,
        iv,
        signature,
        clientPrivateKeyForDecryptRef.current,
        serverPublicKeyForVerifyRef.current
      );

      setData(decryptedPayload);

      if (fallbackUsed) {
        alert(
          `The latest data may have been tampered with. Previous version was used as fallback. Data = ${decryptedPayload}`
        );
      } else {
        alert(`Data is verified, data = ${decryptedPayload}`);
      }
    } catch (error) {
      alert("Data is corrupted or tempered, please contact support");
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
      <div style={{ display: "flex", gap: "10px" }}>
        <button
          onClick={sendData}
          style={{ padding: "10px 20px", fontSize: "16px" }}
        >
          Send Data
        </button>
        <button
          style={{ padding: "10px 20px", fontSize: "16px" }}
          onClick={fetchAndVerifyData}
        >
          Verify Data
        </button>
      </div>
    </div>
  );
}

export default App;
