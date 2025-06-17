import { WebSocketServer, WebSocket } from "ws";


const wss = new WebSocketServer({ port: 8080 });

const userSockets = new Map<string, WebSocket>();

interface PublicBundle {
  ik: string;
  spk: string;
  spkSig: string;
  opk?: string;
}

const userBundles = new Map<string, { bundle: PublicBundle, dhPublicKey: any }>();

// const sharedSecret = randomBytes(32); // Simulated shared secret for all users

wss.on("connection", function connection(ws) {
  let currentUsername: string | null = null;

  ws.on("error", console.error);

  ws.on("message", function message(data) {
    try {
      const parsed = JSON.parse(data.toString());

      // 1.Register a new user (username + X3DH key bundle)
      if (parsed.type === "register") {
        const { username, bundle, dhPublicKey } = parsed;
        if (typeof username !== "string" || !bundle || typeof bundle !== "object") {
          ws.send(JSON.stringify({ error: "Invalid registration data" }));
          return;
        }

        currentUsername = username;
        userSockets.set(username, ws);
        userBundles.set(username, { bundle, dhPublicKey });

        ws.send(JSON.stringify({ type: "registered", username }));
        console.log(`User registered: ${username} with X3DH bundle`);
      }

      //2. envoi du bundle d'un utilisateur
      else if (parsed.type === "getBundle") {
        const { username } = parsed;
        const bundle = userBundles.get(username)?.bundle;

        if (!bundle) {
          ws.send(JSON.stringify({ error: "No bundle found for " + username }));
          return;
        }

        ws.send(JSON.stringify({
          type: "bundleResponse",
          from: username,
          bundle
        }));
      }

      // 3. envoi des données de partage de secret
      else if (parsed.type === "secretSharing") {
        const { to, sharedSecretData } = parsed;
        const target = userSockets.get(to);
        if (!currentUsername) {
          ws.send(JSON.stringify({ error: "User not registered" }));
          return;
        }
        if (!target) {
          ws.send(JSON.stringify({ error: `User '${to}' not found` }));
          return;
        }

        const publicKey = userBundles.get(currentUsername)?.dhPublicKey
        target.send(
          JSON.stringify({
            type: "secretSharing",
            from: currentUsername,
            sharedSecretData,
            publicKey
          })
        );
      }

      // 2. Send a message to another user
      else if (parsed.type === "message") {
        const { to, content } = parsed;
        const target = userSockets.get(to);

        if (!currentUsername) {
          ws.send(JSON.stringify({ error: "User not registered" }));
          return;
        }

        if (!target) {
          ws.send(JSON.stringify({ error: `User '${to}' not found` }));
          return;
        }

        console.log(`Content from ${currentUsername} to ${to}: ${content}`);

        target.send(
          JSON.stringify({
            type: "message",
            from: currentUsername,
            content,
          })
        );
      }

      // 4. Unknown message type
      else {
        ws.send(JSON.stringify({ error: "Unknown message type" }));
      }
    } catch (err) {
      ws.send(JSON.stringify({ error: "Invalid message format" }));
    }
  });

  ws.on("close", () => {
    if (currentUsername) {
      userSockets.delete(currentUsername);
      console.log(`User disconnected: ${currentUsername}`);
    }
  });
});
