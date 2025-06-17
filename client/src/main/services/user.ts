import {
  calculateSharedSecret,
  decrypt,
  encrypt,
  generateDHKeyPair,
  KDFChainKey,
  KDFRootKey,
} from "../helpers/double_ratchet";
import { createPublicKey, KeyObject } from "crypto";
import { Header } from "../types/header";
import { Message } from "../types/message";

export class User {
  MAX_SKIPPED_MESSAGES = 100;

  name: string;
  DH: {
    publicKey: KeyObject;
    privateKey: KeyObject;
  };
  rootKey: Buffer | null;
  chainKeySend: Buffer | null;
  chainKeyRecv: Buffer | null;
  publicKeyReceived: KeyObject | null;
  sendingCount: number;
  receivingCount: number;
  previousSendingCount: number; // Number of messages in previous sending chain
  skippedMessageKeys: Map<string, Buffer>; // Map to store skipped message keys

  constructor(name: string) {
    this.name = name;
    this.DH = generateDHKeyPair();
    this.rootKey = null;

    this.chainKeySend = null;
    this.chainKeyRecv = null;

    this.publicKeyReceived = null;

    this.sendingCount = 0;
    this.receivingCount = 0;
    this.previousSendingCount = 0;

    this.skippedMessageKeys = new Map();
  }

  exportPublicKey(): string {
    return this.DH.publicKey
      .export({ type: "spki", format: "pem" })
      .toString("utf-8");
  }

  importPublicKey(publicKey: string): KeyObject {
    const publicKeyBuffer = Buffer.from(publicKey, "utf-8");
    const publicKeyObj = createPublicKey({
      key: publicKeyBuffer,
      format: "pem",
      type: "spki",
    });
    if (!publicKeyObj || publicKeyObj.type !== "public") {
      throw new Error("Invalid public key provided.");
    }

    return publicKeyObj;
  }

  isInitialized(): boolean {
    return this.rootKey !== null;
  }

  initSender(masterKey: Buffer, remotePubKey: KeyObject) {
    this.rootKey = masterKey;
    this.publicKeyReceived = remotePubKey;

    const dhSharedSecret = calculateSharedSecret(
      this.DH.privateKey,
      remotePubKey
    );
    const { rootKey, chainKey } = KDFRootKey(this.rootKey, dhSharedSecret);

    this.rootKey = rootKey;
    this.chainKeySend = chainKey;
  }

  initReceiver(masterKey: Buffer) {
    this.rootKey = masterKey;
  }

  sendMessage(plaintext: string, associatedData = Buffer.alloc(0)): Message {
    if (!this.chainKeySend) {
      throw new Error("Sender not initialized. Call initSender first.");
    }

    const { chainKey, messageKey } = KDFChainKey(this.chainKeySend);
    this.chainKeySend = chainKey;

    const header = new Header(
      this.DH.publicKey,
      this.previousSendingCount,
      this.sendingCount
    );

    this.sendingCount++;

    const ciphertext = encrypt(
      messageKey,
      plaintext,
      Buffer.concat([header.toBuffer(), associatedData])
    );

    return new Message(header, ciphertext);
  }

  receiveMessage(msg: Message, associated_data = Buffer.alloc(0)) {
    if (!this.rootKey) {
      throw new Error("Receiver not initialized. Call initReceiver first.");
    }

    const { header, ciphertext } = msg;

    const plaintext = this.#trySkippedMessageKeys(
      header,
      ciphertext,
      associated_data
    );
    if (plaintext) {
      return plaintext;
    }

    if (!this.publicKeyReceived || !header.pk.equals(this.publicKeyReceived)) {
      // If the public key has changed, we need to ratchet
      // the DH keys and update the root key and chain key
      // and store the skipped message keys
      this.#storeSkippedMessageKey(header.pn);
      this.#DHRatchet(header);
    }

    this.#storeSkippedMessageKey(header.n);
    const { chainKey, messageKey } = KDFChainKey(this.chainKeyRecv!);
    this.chainKeyRecv = chainKey;
    this.receivingCount++;

    return decrypt(
      messageKey,
      ciphertext,
      Buffer.concat([header.toBuffer(), associated_data])
    );
  }

  #trySkippedMessageKeys(
    header: Header,
    ciphertext: Buffer,
    associated_data: Buffer
  ) {
    const key = this.#keyMap(header.pk, header.n);
    const messageKey = this.skippedMessageKeys.get(key);
    if (messageKey) {
      this.skippedMessageKeys.delete(key);
      return decrypt(
        messageKey,
        ciphertext,
        Buffer.concat([header.toBuffer(), associated_data])
      );
    }
    return null;
  }

  #storeSkippedMessageKey(until: number) {
    if (this.receivingCount + until > this.MAX_SKIPPED_MESSAGES) {
      throw new Error(
        `Cannot store more than ${this.MAX_SKIPPED_MESSAGES} skipped messages.`
      );
    }

    if (this.chainKeyRecv) {
      while (this.receivingCount < until) {
        const { chainKey, messageKey } = KDFChainKey(this.chainKeyRecv);
        this.chainKeyRecv = chainKey;
        const key = this.#keyMap(this.publicKeyReceived!, this.receivingCount);
        this.skippedMessageKeys.set(key, messageKey);
        this.receivingCount++;
      }
    }
  }

  #DHRatchet(header: Header) {
    this.previousSendingCount = this.sendingCount;
    this.sendingCount = 0;
    this.receivingCount = 0;

    this.publicKeyReceived = header.pk;

    const { rootKey, chainKey } = KDFRootKey(
      this.rootKey!,
      calculateSharedSecret(this.DH.privateKey, header.pk)
    );
    console.log("First DH ratchet with new public key");
    this.rootKey = rootKey;
    this.chainKeyRecv = chainKey;
    this.DH = generateDHKeyPair(); // Generate new DH keys for future messages
    const { rootKey: newRootKey, chainKey: newChainKey } = KDFRootKey(
      this.rootKey!,
      calculateSharedSecret(this.DH.privateKey, header.pk)
    );
    console.log("New root key and chain key after DH ratchet:");
    this.rootKey = newRootKey;
    this.chainKeySend = newChainKey;
  }

  #keyMap(publicKey: KeyObject, index: number): string {
    return `${publicKey
      .export({ type: "spki", format: "der" })
      .toString("hex")}_${index}`;
  }
}
