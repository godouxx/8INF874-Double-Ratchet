import WebSocket from "ws";
import { User } from "./user";
import { Message } from "../types/message";

class UserSession {
  #username = "";
  #contactPerson = "";
  #ws: WebSocket | null = null;
  #serverUrl = "ws://localhost:8080";
  #user: User;
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

    this.#ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === "message" && msg.from && msg.content) {
          const message = Message.deserialize(msg.content);

          const plaintext = this.#user.receiveMessage(message);

          this.#messageListener(msg.from, plaintext);
        } else if (msg.type === "publicKey") {
          const sharedSecret = Buffer.from(msg.sharedSecret);

          this.#user.initSender(sharedSecret, msg.publicKey);
        } else if (msg.type === "firstMessage") {
          const message = Message.deserialize(msg.content);

          const sharedSecret = Buffer.from(msg.sharedSecret);
          this.#user.initReceiver(sharedSecret);

          const plaintext = this.#user.receiveMessage(message);
          console.log(`First message from ${msg.from}: ${plaintext}`);
        } else {
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

  #sendRegister() {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      this.#ws.send(
        JSON.stringify({
          type: "register",
          username: this.#username,
        })
      );
    }
  }

  #connectToUser() {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }

    if (!this.#contactPerson || this.#contactPerson.trim() === "") {
      throw new Error("Contact person cannot be empty");
    }

    if (!this.#user.isInitialized()) {
      console.log(`Sending public key to ${this.#contactPerson}...`);
      this.#ws.send(
        JSON.stringify({
          type: "publicKey",
          to: this.#contactPerson,
          publicKey: this.#user.exportPublicKey(),
        })
      );
    } else {
      console.log(`Connecting to ${this.#contactPerson}...`);
      this.sendFirstMessage(
        `Hello ${this.#contactPerson}, I am ${this.#username}. Let's chat!`
      );
    }
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
}

// Singleton export
export const userSession = new UserSession();
