// message.ts
import { Header } from "./header";

class Message {
  header: Header;
  ciphertext: Buffer;

  constructor(header: Header, ciphertext: Buffer) {
    this.header = header;
    this.ciphertext = ciphertext;
  }

  serialize(): string {
    return JSON.stringify({
      header: this.header.serialize(),
      ciphertext: this.ciphertext.toString("base64"),
    });
  }

  static deserialize(serialized: string): Message {
    const parsed = JSON.parse(serialized);

    return new Message(
      Header.deserialize(parsed.header),
      Buffer.from(parsed.ciphertext, "base64")
    );
  }
}

export { Message };
