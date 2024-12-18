import CryptoJS from "crypto-js";
import {
  SERVER_PUBLIC_KEY,
  CLIENT_PRIVATE_KEY,
  SALT_LENGTH,
} from "../constants/keys.constants.ts";

function pemToBuffer(pem: string): ArrayBuffer {
  const cleanPem = pem.replace(/-----BEGIN .*-----|-----END .*-----|\n/g, "");
  const binary = atob(cleanPem);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function encodeBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function importServerPublicKeyForEncrypt(pem: string) {
  return await crypto.subtle.importKey(
    "spki",
    pemToBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

async function importServerPublicKeyForVerify(pem: string) {
  return await crypto.subtle.importKey(
    "spki",
    pemToBuffer(pem),
    {
      name: "RSA-PSS",
      hash: { name: "SHA-256" },
    },
    false,
    ["verify"]
  );
}

async function importClientPrivateKeyForDecrypt(pem: string) {
  return await crypto.subtle.importKey(
    "pkcs8",
    pemToBuffer(pem),
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" },
    },
    false,
    ["decrypt"]
  );
}

async function importClientPrivateKeyForSigning(pem: string) {
  return await crypto.subtle.importKey(
    "pkcs8",
    pemToBuffer(pem),
    {
      name: "RSA-PSS",
      hash: { name: "SHA-256" },
    },
    false,
    ["sign"]
  );
}

async function signData(
  data: ArrayBuffer,
  privateKey: CryptoKey
): Promise<string> {
  const signature = await crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: SALT_LENGTH,
    },
    privateKey,
    data
  );
  return encodeBase64(signature);
}

async function encryptAESKey(
  aesKey: string,
  publicKey: CryptoKey
): Promise<string> {
  const exportedAESKey = new TextEncoder().encode(aesKey);

  const encryptedAESKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    exportedAESKey
  );

  return encodeBase64(encryptedAESKey);
}

const encryptPayloadWithAES = (plaintext: string, key: string) => {
  const iv = CryptoJS.lib.WordArray.random(16);
  const ciphertext = CryptoJS.AES.encrypt(
    plaintext,
    CryptoJS.enc.Hex.parse(key),
    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  );

  return {
    encryptedData: ciphertext.toString(),
    iv: iv.toString(CryptoJS.enc.Base64),
  };
};

export async function loadKeysAndGenerateAES(): Promise<{
  serverPublicKeyForEncrypt: CryptoKey;
  serverPublicKeyForVerify: CryptoKey;
  clientPrivateKeyForSigning: CryptoKey;
  clientPrivateKeyForDecrypt: CryptoKey;
  aesKey: string;
}> {
  try {
    const serverPublicKeyForEncrypt = await importServerPublicKeyForEncrypt(
      SERVER_PUBLIC_KEY
    );
    const serverPublicKeyForVerify = await importServerPublicKeyForVerify(
      SERVER_PUBLIC_KEY
    );
    const clientPrivateKeyForSigning = await importClientPrivateKeyForSigning(
      CLIENT_PRIVATE_KEY
    );
    const clientPrivateKeyForDecrypt = await importClientPrivateKeyForDecrypt(
      CLIENT_PRIVATE_KEY
    );

    const aesKey = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);

    return {
      serverPublicKeyForEncrypt,
      serverPublicKeyForVerify,
      clientPrivateKeyForSigning,
      clientPrivateKeyForDecrypt,
      aesKey,
    };
  } catch (error) {
    console.error("Error loading keys and generating AES key:", error);
    throw error;
  }
}

export async function encryptData(
  data: string,
  aesKey: string,
  serverPublicKey: CryptoKey,
  clientPrivateKey: CryptoKey
): Promise<{
  encryptedData: string;
  encryptedAESKey: string;
  iv: string;
  signature: string;
}> {
  try {
    // Encrypt the payload with AES
    const { encryptedData, iv } = encryptPayloadWithAES(data, aesKey);

    // Encrypt the AES key with the server's RSA public key
    const encryptedAESKey = await encryptAESKey(aesKey, serverPublicKey);

    // Sign the original data with the client's private key
    const signature = await signData(
      new TextEncoder().encode(data),
      clientPrivateKey
    );

    return {
      encryptedData,
      encryptedAESKey,
      iv,
      signature,
    };
  } catch (error) {
    console.error("Error preparing data for the server:", error);
    throw error;
  }
}

async function decryptAESKey(
  encryptedAESKey: string,
  clientPrivateKeyForDecrypt: CryptoKey
): Promise<string> {
  try {
    const decryptedAESKeyBuffer = await crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      clientPrivateKeyForDecrypt,
      Uint8Array.from(atob(encryptedAESKey), (c) => c.charCodeAt(0)) // Base64-decoded RSA-encrypted AES key
    );

    const decryptedAESKey = Array.from(new Uint8Array(decryptedAESKeyBuffer))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    return decryptedAESKey;
  } catch (error) {
    console.error("Error decrypting AES key:", error);
    throw new Error("Failed to decrypt AES key");
  }
}

async function verifySignature(
  decryptedPayload: string,
  signature: string,
  serverPublicKeyForVerify: CryptoKey
): Promise<boolean> {
  try {
    const encodedPayload = new TextEncoder().encode(decryptedPayload);
    const decodedSignature = Uint8Array.from(atob(signature), (c) =>
      c.charCodeAt(0)
    );

    const isVerified = await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: SALT_LENGTH,
      },
      serverPublicKeyForVerify,
      decodedSignature,
      encodedPayload
    );

    return isVerified;
  } catch (error) {
    console.error("Error verifying signature:", error);
    return false;
  }
}

export async function decryptAndVerifyData(
  encryptedData: string,
  encryptedAESKey: string,
  iv: string,
  signature: string,
  clientPrivateKeyForDecrypt: CryptoKey,
  serverPublicKeyForVerify: CryptoKey
): Promise<string> {
  try {
    // Decrypt the AES key with the client's private RSA key
    const decryptedAESKey = await decryptAESKey(
      encryptedAESKey,
      clientPrivateKeyForDecrypt
    );

    // Decrypt the payload using AES
    const decryptedPayload = CryptoJS.AES.decrypt(
      encryptedData,
      CryptoJS.enc.Hex.parse(decryptedAESKey),
      {
        iv: CryptoJS.enc.Base64.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    ).toString(CryptoJS.enc.Utf8);

    // Verify the signature using the server's public key
    const isVerified = await verifySignature(
      decryptedPayload,
      signature,
      serverPublicKeyForVerify
    );

    if (isVerified) {
      return decryptedPayload;
    } else {
      throw new Error(
        "Signature verification failed. Data might have been tampered with."
      );
    }
  } catch (error) {
    throw new Error("Failed to decrypt or verify data.");
  }
}
