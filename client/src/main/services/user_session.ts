import WebSocket from "ws";
import { User } from "./user";
import { Message } from "../types/message";
import { randomBytes, createCipheriv, createDecipheriv, KeyPairKeyObjectResult, createPublicKey, KeyObject, createPrivateKey, verify } from "crypto";
import {
  generateSignedPreKey,
  generateKeyPair,
  x3dhInitiator,
  x3dhResponder,
} from "../helpers/x3dh";

class UserSession {
  #username = "";
  #contactPerson = "";
  #ws: WebSocket | null = null;
  #serverUrl = "ws://localhost:8080";
  #user: User;
  #localKeyMaterial: {
    ik: KeyPairKeyObjectResult;
    spk: KeyPairKeyObjectResult;
    spkSig: Uint8Array;
    opk: KeyPairKeyObjectResult;
  } | null = null;
  #masterKey: Uint8Array | null = null;
  #messageListener: (from: string, content: string) => void;

  set username(username: string) {
    if (!username || username.trim() === "") {
      throw new Error("Username cannot be empty");
    }

    this.#username = username;
    try {
      this.#user = new User(this.#username);
    } catch (err) {
      console.log(`Failed to initialize user`);
    }
    this.#connectWebSocket();
  }

  get username() {
    return this.#username;
  }

  set contactPerson(contact: string) {
    if (!contact || contact.trim() === "") {
      throw new Error("Contact name cannot be empty");
    }

    this.#contactPerson = contact;
    this.#connectToUser();
  }

  get contactPerson() {
    return this.#contactPerson;
  }

  get socket() {
    return this.#ws;
  }

  #connectWebSocket() {
    // Si déjà connecté et prêt, on n’envoie que le message d’enregistrement
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      this.#sendRegister();
      return;
    }

    // Sinon on crée une nouvelle connexion
    this.#ws = new WebSocket(this.#serverUrl);

    this.#ws.on("open", () => {
      console.log("WebSocket connected");
      this.#sendRegister();
    });

    this.#ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === "message" && msg.from && msg.content) {
          const message = Message.deserialize(msg.content);

          const plaintext = this.#user.receiveMessage(message);
          if(plaintext != 'FIRSTMESSAGE') {
            this.#messageListener(msg.from, plaintext);
          }

        } 

        // initialisation du partage de secret X3DH et calcul du secret partagé
        else if (msg.type === "bundleResponse" && msg.from === this.#contactPerson) {

          const ikRemote: KeyObject = KeyObjectFromBase64(msg.bundle.ik, 'public');
          const spkRemote: KeyObject = KeyObjectFromBase64(msg.bundle.spk, 'public');
          const opkRemote: KeyObject = KeyObjectFromBase64(msg.bundle.opk, 'public');
          const ephemeralKeyPair = generateKeyPair();

          const masterKey = await x3dhInitiator(
            this.#localKeyMaterial!.ik.privateKey,
            ephemeralKeyPair.privateKey,
            ikRemote,
            spkRemote,
            opkRemote
          );

          this.#masterKey = masterKey;;

          console.log(`Secret partage etabli avec ${msg.from}`);
          this.#user.initReceiver(Buffer.from(this.#masterKey!));

          //calculer associated data
          const AD = computeAD(this.#localKeyMaterial!.ik.publicKey, ikRemote);
          const { ciphertext, iv, tag } = encryptAD(AD, masterKey);
          
          // verification des clés
          const verifAD = new Uint8Array(await crypto.subtle.digest("SHA-256", AD))


          const sharedSecretData = {
            publicKey: keyObjectToBase64(this.#localKeyMaterial!.ik.publicKey),
            ephemeralPublicKey: keyObjectToBase64(ephemeralKeyPair.publicKey),
            associatedData: toBase64(ciphertext),
            opk: opkRemote ? opkRemote : null,
            iv: toBase64(iv),
            tag: toBase64(tag)
          };

          this.#ws!.send(
            JSON.stringify({
              type: "secretSharing",
              to: msg.from,
              sharedSecretData
            })
          );
        }

        // Réception des données de partage de secret et calcul du secret partagé
        else if (msg.type === "secretSharing") {

          const epk: KeyObject = KeyObjectFromBase64(msg.sharedSecretData.ephemeralPublicKey, 'public')
          const ikRemote: KeyObject = KeyObjectFromBase64(msg.sharedSecretData.publicKey, 'public');
          const opkUsed: KeyObject = this.#localKeyMaterial!.opk.privateKey;

          const masterKey = await x3dhResponder(
            this.#localKeyMaterial!.ik.privateKey,
            this.#localKeyMaterial!.spk.privateKey,
            epk,
            ikRemote,
            opkUsed
          );
          this.#masterKey = masterKey;

          const iv = fromBase64(msg.sharedSecretData.iv);
          const tag = fromBase64(msg.sharedSecretData.tag);
          const ciphertext = fromBase64(msg.sharedSecretData.associatedData);

          const expectedAD = computeAD(
            ikRemote,
            this.#localKeyMaterial!.ik.publicKey,
          );
          const isValid = decryptAndVerifyAD(Buffer.from(iv), Buffer.from(ciphertext), Buffer.from(tag), masterKey, expectedAD);
          // verification des clés
          const verifAD = new Uint8Array(await crypto.subtle.digest("SHA-256", expectedAD))

          if (!isValid) {
            console.error("AD mismatch! Decryption failed or keys do not match.");
            return;
          } else {
            const remoteDHPK = this.#user.importPublicKey(msg.publicKey);
            this.#user.initSender(Buffer.from(this.#masterKey), remoteDHPK);
          }
        }

        else {
          console.log("Server message:", msg);
        }
      } catch (err) {
        console.error("Failed to parse message", err);
      }
    });

    this.#ws.on("close", () => {
      console.log("WebSocket disconnected");
      this.#ws = null;
    });

    this.#ws.on("error", (err) => {
      console.error("WebSocket error:", err);
    });
  }

  // enregistre l'utilisateur auprès du serveur
  #sendRegister() {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      const ik = generateKeyPair();
      const { spk, signature } = generateSignedPreKey(ik.privateKey);
      const opk = generateKeyPair();

      // stocke les clés privées localement si nécessaire
      this.#localKeyMaterial = {
        ik,
        spk,
        spkSig: signature,
        opk
      };

      const bundle = {
        ik: keyObjectToBase64(ik.publicKey),
        spk: keyObjectToBase64(spk.publicKey),
        spkSig: toBase64(signature),
        opk: keyObjectToBase64(opk.publicKey)
      };

      this.#ws.send(
        JSON.stringify({
          type: "register",
          username: this.#username,
          bundle,
          dhPublicKey: this.#user.exportPublicKey(),
        })
      );
    }
  }

  // Connecte l'utilisateur à un autre utilisateur
  async #connectToUser() {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }

    if (!this.#contactPerson || this.#contactPerson.trim() === "") {
      throw new Error("Contact person cannot be empty");
    }

    // Si l'utilisateur n’a pas encore été initialisé (pas de ratchet)
    if (!this.#user.isInitialized()) {
      this.#ws.send(
        JSON.stringify({
          type: "getBundle",
          username: this.#contactPerson
        })
      );
      return;
    }

    // Sinon, si déjà initialisé, on peut envoyer un message directement
    console.log(`Connecting to ${this.#contactPerson}...`);
    this.sendMessage(
      this.#contactPerson,
      `FIRSTMESSAGE`
    );
  }

  sendMessage(to: string, content: string) {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }

    const encryptedMessage = this.#user.sendMessage(content);

    this.#ws.send(
      JSON.stringify({
        type: "message",
        to,
        content: encryptedMessage.serialize(),
      })
    );
  }

  sendFirstMessage(content: string) {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }

    if (!this.#contactPerson || this.#contactPerson.trim() === "") {
      throw new Error("Contact person cannot be empty");
    }

    const encryptedMessage = this.#user.sendMessage(content);

    this.#ws.send(
      JSON.stringify({
        type: "firstMessage",
        to: this.#contactPerson,
        content: encryptedMessage.serialize(),
      })
    );
  }

  onMessage(callback: (from: string, content: string) => void) {
    this.#messageListener = callback;
  }

  storeKeyMaterial({ ik, spk, spkSig, opk }: {
    ik: KeyPairKeyObjectResult;
    spk: KeyPairKeyObjectResult;
    spkSig: Uint8Array;
    opk: KeyPairKeyObjectResult;
  }) {
    this.#localKeyMaterial = { ik, spk, spkSig, opk };
  }

}

// Fonction pour convertir un Uint8Array en chaîne Base64
function toBase64(u8: Uint8Array): string {
  return Buffer.from(u8).toString("base64");
}

// Fonction pour convertir un KeyObject en chaîne Base64
function keyObjectToBase64(key: KeyObject): string {
  return key.export({ format: 'der', type: 'spki' }).toString('base64');
}

// Fonction pour convertir une chaîne Base64 en Uint8Array
function fromBase64(str: string): Uint8Array {
  return Uint8Array.from(Buffer.from(str, "base64"));
}

// Fonction pour convertir une chaîne Base64 en KeyObject
export function KeyObjectFromBase64(base64Str: string, type: 'public' | 'private'): KeyObject {
  const der = Buffer.from(base64Str, 'base64');

  if (type === 'public') {
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } else if (type === 'private') {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } else {
    throw new Error("Invalid type, expected 'public' or 'private'");
  }
}

// Fonction pour construire AD = IKA || IKB
export function computeAD(IKA: KeyObject, IKB: KeyObject): Uint8Array {
  const ikaBytes = IKA.export({ format: 'der', type: 'spki' }) as Buffer;
  const ikbBytes = IKB.export({ format: 'der', type: 'spki' }) as Buffer;

  const ad = new Uint8Array(ikaBytes.length + ikbBytes.length);
  ad.set(ikaBytes, 0);
  ad.set(ikbBytes, ikaBytes.length);

  return ad;
}

// Chiffre AD avec AES-GCM en utilisant la masterKey
export function encryptAD(
  ad: Uint8Array,
  masterKey: Buffer
): { iv: Buffer; ciphertext: Buffer; tag: Buffer } {
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes for AES-256-GCM");
  }

  const iv = randomBytes(12); // 96-bit IV

  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(ad), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { iv, ciphertext, tag };
}

// Déchiffre AD pour vérifier l'authenticité avec la masterKey
export function decryptAndVerifyAD(
  iv: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  masterKey: Buffer,
  expectedAD: Uint8Array
): boolean {
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes for AES-256-GCM");
  }

  const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(tag);

  let decrypted: Buffer;
  try {
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return false;
  }

  return Buffer.compare(decrypted, Buffer.from(expectedAD)) === 0;
}

// Singleton export
export const userSession = new UserSession();
