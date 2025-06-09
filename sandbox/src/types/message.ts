import { Header } from "./header.js";

interface Message {
  header: Header;
  ciphertext: Buffer;
}

export type { Message };
