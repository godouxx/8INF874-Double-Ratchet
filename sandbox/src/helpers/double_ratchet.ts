import {
  BinaryLike,
  createCipheriv,
  createDecipheriv,
  createHmac,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  KeyObject,
} from "crypto";

const DH_TYPE = "x448";
const ROOT_KEY_INFO = Buffer.from("DoubleRatchetRootKey", "utf-8");
const MESSAGE_KEY_INFO = Buffer.from("DoubleRatchetMessageKey", "utf-8");

function generateDHKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync(DH_TYPE);
  return { publicKey, privateKey };
}

function calculateSharedSecret(
  userPrivateKey: KeyObject,
  partnerPublicKey: KeyObject
) {
  try {
    const sharedSecret = diffieHellman({
      privateKey: userPrivateKey,
      publicKey: partnerPublicKey,
    });
    return sharedSecret;
  } catch (err) {
    throw new Error("Invalid public key for DH exchange");
  }
}

function KDFRootKey(rootKey: Buffer, sharedSecret: Buffer) {
  const length = 64; // 32 bytes for rootKey, 32 bytes for chainKey

  const derived = hkdfSync(
    "sha256",
    sharedSecret,
    rootKey,
    ROOT_KEY_INFO,
    length
  );

  const derivedRootKey = derived.slice(0, 32);
  const derivedChainKey = derived.slice(32, 64);

  return {
    rootKey: Buffer.from(derivedRootKey),
    chainKey: Buffer.from(derivedChainKey),
  };
}

function KDFChainKey(chainKey: BinaryLike) {
  const messageKey = createHmac("sha256", chainKey)
    .update(Buffer.from([0x01]))
    .digest();
  const nextChainKey = createHmac("sha256", chainKey)
    .update(Buffer.from([0x02]))
    .digest();

  return {
    messageKey: messageKey.subarray(0, 32),
    chainKey: nextChainKey.subarray(0, 32),
  };
}

function encrypt(
  key: Buffer,
  plaintext: string,
  associated_data: BinaryLike = Buffer.alloc(0)
) {
  const hashLength = 32; // SHA-256 output size
  const hkdfSalt = Buffer.alloc(hashLength, 0); // zero-filled
  const totalLength = 32 + 32 + 16; // encryptionKey + authKey + IV = 80 bytes

  const derived = hkdfSync(
    "sha256",
    key,
    hkdfSalt,
    MESSAGE_KEY_INFO,
    totalLength
  );

  const encryptionKey = derived.slice(0, 32);
  const authKey = derived.slice(32, 64);
  const iv = derived.slice(64, 80);

  // AES-CBC encryption with PKCS#7 padding
  const algorithm = "aes-256-cbc";
  const cipher = createCipheriv(
    algorithm,
    Buffer.from(encryptionKey),
    Buffer.from(iv)
  );
  let ciphertext = cipher.update(plaintext);
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);

  // Create HMAC over associated_data || ciphertext
  const hmac = createHmac("sha256", Buffer.from(authKey));
  hmac.update(associated_data);
  hmac.update(ciphertext);
  const tag = hmac.digest(); // 32 bytes

  // Return ciphertext || tag
  return Buffer.concat([ciphertext, tag]);
}

function decrypt(
  key: Buffer,
  ciphertext: Buffer,
  associatedData: BinaryLike = Buffer.alloc(0)
) {
  const hashLength = 32; // SHA-256 output size
  const hkdfSalt = Buffer.alloc(hashLength, 0); // zero-filled
  const totalLength = 32 + 32 + 16; // encryptionKey + authKey + IV = 80 bytes

  const derived = hkdfSync(
    "sha256",
    key,
    hkdfSalt,
    MESSAGE_KEY_INFO,
    totalLength
  );

  const encryptionKey = derived.slice(0, 32);
  const authKey = derived.slice(32, 64);
  const iv = derived.slice(64, 80);

  // Verify HMAC tag
  const tag = ciphertext.slice(-32);
  const hmac = createHmac("sha256", Buffer.from(authKey));
  hmac.update(associatedData);
  hmac.update(ciphertext.slice(0, -32));

  if (!hmac.digest().equals(tag)) {
    throw new Error("Invalid HMAC tag");
  }

  // AES-CBC decryption with PKCS#7 padding
  const algorithm = "aes-256-cbc";
  const decipher = createDecipheriv(
    algorithm,
    Buffer.from(encryptionKey),
    Buffer.from(iv)
  );
  let plaintext = decipher.update(ciphertext.subarray(0, -32));
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString("utf-8");
}

export {
  generateDHKeyPair,
  calculateSharedSecret,
  KDFRootKey,
  KDFChainKey,
  encrypt,
  decrypt,
};
