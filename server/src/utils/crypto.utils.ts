import crypto from "crypto";
import {
  SERVER_PRIVATE_KEY,
  CLIENT_PUBLIC_KEY,
  SALT_LENGTH,
} from "../constants/keys.constants";
import CryptoJS from "crypto-js";

function decodeBase64(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}

function decryptAESKey(encryptedAESKey: string): Buffer {
  try {
    const decryptedAESKeyBuffer = crypto.privateDecrypt(
      {
        key: SERVER_PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      decodeBase64(encryptedAESKey)
    );

    return Buffer.from(decryptedAESKeyBuffer.toString("utf8"), "hex");
  } catch (error) {
    console.error("Error decrypting AES key:", error);
    throw new Error("Failed to decrypt AES key");
  }
}

function decryptPayload(
  encryptedData: string,
  aesKey: Buffer,
  iv: string
): string {
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      aesKey,
      decodeBase64(iv)
    );

    let decryptedPayload = decipher.update(
      decodeBase64(encryptedData),
      undefined,
      "utf8"
    );
    decryptedPayload += decipher.final("utf8");

    return decryptedPayload;
  } catch (error) {
    console.error("Error decrypting payload:", error);
    throw new Error("Failed to decrypt payload");
  }
}

function verifySignature(decryptedPayload: string, signature: string): boolean {
  try {
    const isVerified = crypto.verify(
      "sha256",
      Buffer.from(decryptedPayload),
      {
        key: CLIENT_PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      decodeBase64(signature)
    );

    return isVerified;
  } catch (error) {
    console.error("Error verifying signature:", error);
    throw new Error("Failed to verify signature");
  }
}

export function verifyAndDecryptData({
  encryptedData,
  encryptedAESKey,
  iv,
  signature,
}: {
  encryptedData: string;
  encryptedAESKey: string;
  iv: string;
  signature: string;
}): string {
  try {
    // Decrypt the AES key
    const aesKey = decryptAESKey(encryptedAESKey);

    // Decrypt the payload
    const decryptedPayload = decryptPayload(encryptedData, aesKey, iv);

    // Verify the signature
    const isVerified = verifySignature(decryptedPayload, signature);
    if (!isVerified) {
      throw new Error("Invalid signature");
    }

    return decryptedPayload;
  } catch (error) {
    if (error instanceof Error) {
      console.error("Error processing or verifying data:", error.message);
    } else {
      console.error("Unknown error processing or verifying data:", error);
    }
    throw error;
  }
}

export function prepareDataForClient(decryptedPayload: string) {
  try {
    // Generate a new AES key
    const aesKey = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex); // 256-bit AES key

    // Encrypt the payload with the new AES key
    const newIv = CryptoJS.lib.WordArray.random(16); // Generate a new 16-byte IV
    const encryptedPayload = CryptoJS.AES.encrypt(
      decryptedPayload,
      CryptoJS.enc.Hex.parse(aesKey), // Parse the key as a WordArray
      {
        iv: newIv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );

    const reEncryptedData = encryptedPayload.ciphertext.toString(
      CryptoJS.enc.Base64
    );

    // Encrypt the new AES key with the client's RSA public key
    const newEncryptedAESKey = crypto.publicEncrypt(
      {
        key: CLIENT_PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(aesKey, "hex")
    );

    // Sign the data with the server's private key using RSA-PSS
    const sign = crypto.createSign("sha256");
    sign.update(decryptedPayload);
    sign.end();
    const newSignature = sign.sign(
      {
        key: SERVER_PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: SALT_LENGTH,
      },
      "base64"
    );

    return {
      encryptedData: reEncryptedData,
      encryptedAESKey: newEncryptedAESKey.toString("base64"),
      iv: newIv.toString(CryptoJS.enc.Base64),
      signature: newSignature,
    };
  } catch (error) {
    console.error("Error preparing data for client:", error);
    throw error;
  }
}
