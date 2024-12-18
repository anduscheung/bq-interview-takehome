export function decodePEM(pem: string): ArrayBuffer {
  const cleanPem = pem.replace(/-----BEGIN .*-----|-----END .*-----|\n/g, "");
  const binary = atob(cleanPem);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function encodeBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

export async function importServerPublicKey(pem: string) {
  return await crypto.subtle.importKey(
    "spki",
    decodePEM(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

export async function importClientPrivateKey(pem: string) {
  return await crypto.subtle.importKey(
    "pkcs8", // Format of the private key
    decodePEM(pem), // Convert PEM to ArrayBuffer
    {
      name: "RSA-PSS", // Specify RSA-PSS algorithm
      hash: { name: "SHA-256" }, // Use SHA-256 for hashing
    },
    false, // Key is not extractable
    ["sign"] // Key can only be used for signing
  );
}

export async function generateAESKey() {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function signData(
  data: ArrayBuffer,
  privateKey: CryptoKey
): Promise<string> {
  const signature = await crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: 32, // Standard salt length
    },
    privateKey,
    data
  );
  return encodeBase64(signature); // Return Base64-encoded signature
}

export async function encryptAESKey(
  aesKey: string, // AES key as a string (Hex or UTF-8)
  publicKey: CryptoKey
): Promise<string> {
  // Convert the string AES key to an ArrayBuffer
  const exportedAESKey = new TextEncoder().encode(aesKey);

  // Encrypt the AES key with the server's RSA public key
  const encryptedAESKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    exportedAESKey
  );

  // Return the encrypted AES key as a Base64 string
  return encodeBase64(encryptedAESKey);
}

export async function encryptPayload(
  payload: string,
  aesKey: CryptoKey
): Promise<{ encryptedData: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM IV
  const encodedPayload = new TextEncoder().encode(payload);

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedPayload
  );

  return {
    encryptedData: encodeBase64(encryptedData),
    iv: encodeBase64(iv),
  };
}
