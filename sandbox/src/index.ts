import { randomBytes } from "crypto";
import { User } from "./models/user.js";

const alice = new User("Alice");
const bob = new User("Bob");

const sharedSecret = randomBytes(32); // simulé
alice.initSender(sharedSecret, bob.DH.publicKey);
bob.initReceiver(sharedSecret);

// Alice envoie un message
const msg = alice.sendMessage("Salut Bob !");
// console.log("[Alice ➜ Bob] Envoi :", msg.ciphertext);
const msg2 = alice.sendMessage("Comment ça va ?");
// console.log("[Alice ➜ Bob] Envoi :", msg2.ciphertext);

console.log("\n");

// Bob reçoit le message
const received = bob.receiveMessage(msg2);
console.log("[Bob 📨] Message reçu :", received);

console.log("\n");

// Bob envoie une réponse
const response = bob.sendMessage("Salut Alice, ça va bien !");
// console.log("[Bob ➜ Alice] Envoi :", response.ciphertext);

console.log("\n");

// Alice reçoit la réponse
const receivedResponse = alice.receiveMessage(response);
console.log("[Alice 📨] Message reçu :", receivedResponse);

console.log("\n");

const aliceMessage = alice.sendMessage("Tu as reçu mon message ?");
// console.log("[Alice ➜ Bob] Envoi :", aliceMessage.ciphertext);
const aliceMessage2 = alice.sendMessage("J'espère que tu vas bien !");
// console.log("[Alice ➜ Bob] Envoi :", aliceMessage2.ciphertext);

console.log("\n");

const skippedMessages = bob.receiveMessage(aliceMessage2);
console.log("[Bob 📨] Messages sautés :", skippedMessages);
const skippedMessages2 = bob.receiveMessage(msg);
console.log("[Bob 📨] Messages sautés :", skippedMessages2);
const skippedMessages3 = bob.receiveMessage(aliceMessage);
console.log("[Bob 📨] Messages sautés :", skippedMessages3);
