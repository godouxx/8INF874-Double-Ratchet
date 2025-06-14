import { randomBytes } from "crypto";
import { User } from "./models/user.js";
import { Message } from "./types/message.js";

const alice = new User("Alice");
const bob = new User("Bob");

const sharedSecret = randomBytes(32); // simulé
alice.initSender(sharedSecret, bob.DH.publicKey);

// Alice envoie un message
const msg = alice.sendMessage("Salut Bob !");
const msg1 = alice.sendMessage("Comment ça va ?");
const serializedMsg = msg.serialize();
const serializedMsg1 = msg1.serialize();
console.log("\n");

// Bob reçoit le message
bob.initReceiver(sharedSecret);
const deserializedMsg = Message.deserialize(serializedMsg);
const deserializedMsg1 = Message.deserialize(serializedMsg1);
const received = bob.receiveMessage(deserializedMsg);
console.log("[Bob 📨] Message reçu :", received);
const received1 = bob.receiveMessage(deserializedMsg1);
console.log("[Bob 📨] Message reçu :", received1);

// const bobMsg = bob.sendMessage("Salut Alice !");
// const serializedBobMsg = bobMsg.serialize();
// const bobMsg1 = bob.sendMessage("Comment ça va ?");
// const serializedBobMsg1 = bobMsg1.serialize();
// console.log("\n");

// // Alice reçoit le message de Bob
// const deserializedBobMsg = Message.deserialize(serializedBobMsg);
// const deserializedBobMsg1 = Message.deserialize(serializedBobMsg1);
// const receivedBob = alice.receiveMessage(deserializedBobMsg);
// const receivedBob1 = alice.receiveMessage(deserializedBobMsg1);
// console.log("[Alice 📨] Message reçu :", receivedBob);
// console.log("[Alice 📨] Message reçu :", receivedBob1);
