import { Header } from "./header";

interface Message {
  header: Header;
  ciphertext: Buffer;
}

export type { Message };
