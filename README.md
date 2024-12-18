# Tamper Proof Data

At Bequest, we require that important user data is tamper proof. Otherwise, our system can incorrectly distribute assets if our internal server or database is breached.

## A note to the author

Hi Anna and Robert,

I wanted to honestly mention that I’m not yet an expert in the field of data security, but it’s definitely an area I’ve been eager to explore. I remember Robert asking me about something I’d like to learn more about as a software engineer—and this was exactly it. To dive deeper, I decided to dedicate around 20 hours to research and develop this solution.

Regardless of the outcome, I want to sincerely thank you both for designing such an engaging and thought-provoking take-home test. It was a great learning experience, and I really enjoyed working on it. :D

## Overview

This project implements a system that ensures data integrity and security for user data being exchanged between a frontend client and a backend server. The system includes encryption and signing of data using RSA and AES algorithms to protect sensitive data. Additionally, it handles data verification and fallback in case of tampered or corrupted data.

The system demonstrates how data can be encrypted and decrypted securely, with mechanisms in place to ensure that if data is tampered with, the client can detect it and recover the most recent valid data from the server.

Key Features:
• AES Encryption for secure data transmission.
• RSA Encryption to protect the AES key during transmission.
• RSA Digital Signatures for data integrity verification.
• Fallback Mechanism to ensure data consistency if tampered data is detected.

### To run the apps:

`npm run start` in both the frontend and backend

## To test the features:

1. Click verify Data, you should see "If I die, my money give to Andus"
2. Make some changes in the text input and click send data, window should prompt "ok", meaning data sent to server
3. Click Verify Data, window should prompt the latest data
4. Visit backend database.csv, remove part of the latest data, click save, go to frontend and click "Verify data", you should see previous data
5. Visit backend database.csv, remove part of the second latest data, go to frontend and click "Verify data", you should see "Data may have been tampered with and no previous data available as fallback"
6. Remove all lines except the header in the DB, go to frontend and click "Verify data", you should see "No data found"

## if you mistakenly removed the DB or you want to reset the DB:

`npm run create-db` in the backend

## Answer to the questions

**1. How does the client ensure that their data has not been tampered with?**

The client ensures that their data has not been tampered with by leveraging encryption and signature verification techniques. When data are sent from client to server, and vice versa, the following are being performed:
• Encryption: Before sending data to the receiver (whether it is the server or client), the sender encrypts the data using AES encryption with a randomly generated AES key. The AES key itself is then encrypted using the receiver’s RSA public key. This ensures that only the receiver, who possesses the corresponding RSA private key, can decrypt the AES key and retrieve the data.
• Signature: In addition to encrypting the data, the sender signs the original plaintext data with their private RSA key before sending it. This signature serves as proof of the integrity of the data. The receiver can verify the signature using the sender’s public RSA key. If the data has been tampered with in transit, the signature verification will fail, indicating that the data is not authentic.
• Decryption: Upon receiving the data, the receiver first decrypts the AES key using their RSA private key. With the decrypted AES key, the receiver can then decrypt the data and retrieve the original content.
• Signature Verification: After decrypting the data, the receiver verifies the signature using the sender’s public RSA key. If the signature matches, it confirms that the data has not been altered during transmission.

Moreover, when the server receives the data, the server directly stores the encrypted data along with its signature into the database. Later, when the server needs to access the data from the database, it performs the verification process again using the stored credentials. This ensures that even if the data has been tampered with in the database, the server will be able to detect the corruption, preserving the integrity of the system.

**2. If the data has been tampered with, how can the client recover the lost data?**

If the data has been tampered with, the system has a fallback mechanism to recover the lost data:

The server stores data in a mock CSV file database, with each new entry the server creates a new row in the CSV. Client will get the latest row if it click the verify button. If the server detects that the most recent data has been tampered with (through failed signature verification), the server will fallback to the second latest valid entry (if available). The server than responds with the fallback data, informing the client that the latest data was corrupted, and the second last entry was used instead. The frontend displays a message notifying the user if fallback data was used. This alerts the user that the most recent data could not be verified and that the system is using an earlier, valid version of the data. This ensures the user is aware of potential data issues and can take appropriate action if necessary.

By implementing this fallback mechanism, the system ensures that even if data is corrupted or tampered with, the client can always access the last known good version of the data without loss of critical information.

## Possible improvement

1. I have put the RSA keys in a constant file for now, but ideally, in a production environment, the keys should be securely stored in a key management system (KMS) or environment variables to ensure that private keys are never exposed to unauthorized entities. In this setup, all clients share the server’s public key because it’s used for encrypting the AES key and verifying the server’s signature. This allows any client to securely communicate with the server.

However, each client has its own private RSA key, which is unique and used for signing data and decrypting the AES key when receiving data. This ensures that private keys are only accessible to the respective clients and never shared.

In production environments, private keys (for each client) are ideally generated securely on the website or locally and stored on the client’s machine, than the public keys are uploaded to the server.

2. For AES encryption and decryption, I initially used the crypto-js library, which provided a convenient solution for both the client and server. However, it is important to note that the maintainer of this library has stated that they will no longer actively develop it. Ideally, I would prefer to use a more actively maintained solution. That said, I encountered difficulties when attempting to use the native Web Crypto API on the client side for AES decryption. After several attempts and due to time constraints, I resorted to using crypto-js, as it provided a working solution.

## The complete flow

1. POST Request Flow (Client → Server)

   Scenario: The client sends data to the server for secure storage.

   1.1 Client-Side:
   • Generate AES Key: The client generates a random AES key (symmetric encryption key).
   • Encrypt AES Key: The client encrypts the AES key using the server’s pre-shared RSA public key to create the encrypted AES key (encry_aes_key).
   • Encrypt Data: The client encrypts the data (raw content) using the generated AES key via AES encryption to produce the ciphertext.
   • Sign the Data: The client signs the raw data using the client’s private RSA key to create a digital signature, ensuring data integrity.
   • Send Data: The client sends the encry_aes_key, ciphertext (encrypted data), IV, and signature to the server in the request.

   1.2 Server-Side:
   • Decrypt AES Key: The server uses its RSA private key to decrypt the encry_aes_key and retrieve the original AES key.
   • Decrypt Data: The server uses the decrypted AES key to decrypt the ciphertext and retrieve the original data.
   • Verify Signature: The server verifies the signature using the client’s public RSA key to ensure that the data has not been tampered with.
   • Encrypt Data for Storage: The server may re-encrypt the data with its own AES key before storing, to ensure secure storage in the database.
   • Store Data: The server stores the encrypted data, encry_aes_key, IV, and signature in the database for future use.

2. GET Request Flow (Server → Client)

Scenario: The server retrieves the encrypted data and sends it back to the client for viewing, ensuring data integrity.

2.1 Server-Side:
• Retrieve Data: The server retrieves the latest stored encrypted data, AES key, IV, and signature from the database.
• Verify Data Integrity: The server checks the integrity of the data by verifying the signature using the client’s public RSA key.
• Decrypt AES Key: If the data is valid, the server uses its RSA private key to decrypt the encry_aes_key and retrieve the original AES key.
• Decrypt Data: The server uses the decrypted AES key and IV to decrypt the stored encrypted data and retrieve the original raw content (data).
• Re-encrypt for Sending: If necessary, the server may re-encrypt the data with a new AES key and send it back to the client.
• Send Data to Client: The server sends the re-encrypted data, encrypted AES key, IV, and signature back to the client.

2.2 Client-Side:
• Receive Data: The client receives the encrypted data, encrypted AES key, IV, and signature from the server.
• Decrypt AES Key: The client uses its private RSA key to decrypt the encrypted AES key.
• Decrypt Data: Using the decrypted AES key and IV, the client decrypts the encrypted data to retrieve the original content.
• Verify Signature: The client verifies the signature using the client’s public RSA key to ensure that the data has not been tampered with.
• Display Data: If the signature is valid, the client displays the decrypted data to the user.
