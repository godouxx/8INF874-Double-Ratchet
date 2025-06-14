import { WebSocketServer, WebSocket } from "ws";
import { randomBytes } from "crypto";

const wss = new WebSocketServer({ port: 8080 });

const userSockets = new Map<string, WebSocket>();

const sharedSecret = randomBytes(32); // Simulated shared secret for all users

wss.on("connection", function connection(ws) {
  let currentUsername: string | null = null;

  ws.on("error", console.error);

  ws.on("message", function message(data) {
    try {
      const parsed = JSON.parse(data.toString());

      // 1.Register a new user
      if (parsed.type === "register") {
        const { username } = parsed;
        if (typeof username !== "string") {
          ws.send(JSON.stringify({ error: "Invalid username" }));
          return;
        }

        currentUsername = username;
        userSockets.set(username, ws);
        ws.send(JSON.stringify({ type: "registered", username }));

        console.log(`User registered: ${username}`);
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

      // 3. Send a public key to another user
      else if (parsed.type === "publicKey") {
        const { to, publicKey } = parsed;
        const target = userSockets.get(to);
        if (!currentUsername) {
          ws.send(JSON.stringify({ error: "User not registered" }));
          return;
        }
        if (!target) {
          ws.send(JSON.stringify({ error: `User '${to}' not found` }));
          return;
        }

        target.send(
          JSON.stringify({
            type: "publicKey",
            from: currentUsername,
            publicKey,
            sharedSecret,
          })
        );
      } else if (parsed.type === "firstMessage") {
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

        // Here you would typically encrypt the content using the shared secret
        // For simplicity, we are sending it as is
        target.send(
          JSON.stringify({
            type: "firstMessage",
            from: currentUsername,
            content,
            sharedSecret,
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
