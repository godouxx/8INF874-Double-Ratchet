import { KDFChainKey } from "./helpers/double_ratchet.js";

console.log("Debugging Double Ratchet Protocol");
const chainKey = Buffer.from(
  "c638463f81a7143a85a00abc6ac7e2b6af7e1bb37d87cce450231748bd42e087",
  "hex"
);

const { messageKey, chainKey: nextChainKey } = KDFChainKey(chainKey);
console.log("Message Key:", messageKey.toString("hex"));
console.log("Next Chain Key:", nextChainKey.toString("hex"));

const { messageKey: messageKey2, chainKey: nextChainKey2 } =
  KDFChainKey(chainKey);
console.log("Message Key 2:", messageKey2.toString("hex"));
console.log("Next Chain Key:", nextChainKey2.toString("hex"));
