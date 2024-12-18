export function decodeBase64(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}
