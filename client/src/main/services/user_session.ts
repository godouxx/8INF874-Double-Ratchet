import WebSocket from "ws";

class UserSession {
  #username = "";
  #contactPerson = "";
  #ws: WebSocket | null = null;
  #serverUrl = "ws://localhost:8080";
  #messageListener: (from: string, content: string) => void;

  set username(username: string) {
    if (!username || username.trim() === "") {
      throw new Error("Username cannot be empty");
    }

    this.#username = username;
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
          this.#messageListener(msg.from, msg.content);
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

  sendMessage(to: string, content: string) {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }

    this.#ws.send(
      JSON.stringify({
        type: "message",
        to,
        content,
      })
    );
  }

  onMessage(callback: (from: string, content: string) => void) {
    this.#messageListener = callback;
  }
}

// Singleton export
export const userSession = new UserSession();
