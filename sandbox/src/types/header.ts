import { createPublicKey, KeyObject } from "crypto";

const KEY_FORMAT_OPTIONS = {
  type: "spki",
  format: "der",
} as const;

class Header {
  pk: KeyObject;
  pn: number;
  n: number;

  constructor(pk: KeyObject, pn: number, n: number) {
    if (!pk || !pk.type || pk.type !== "public") {
      throw new Error("Invalid public key provided");
    }

    this.pk = pk;
    this.pn = pn;
    this.n = n;
  }

  serialize(): string {
    return JSON.stringify({
      pk: this.pk.export(KEY_FORMAT_OPTIONS),
      pn: this.pn,
      n: this.n,
    });
  }

  toBuffer(): Buffer {
    return Buffer.from(this.serialize());
  }

  static deserialize(data: string): Header {
    const parsed = JSON.parse(data);

    if (
      typeof parsed !== "object" ||
      !parsed.pk ||
      typeof parsed.pn !== "number" ||
      typeof parsed.n !== "number"
    ) {
      throw new Error("Invalid header format");
    }

    const keyBuffer = Buffer.from(parsed.pk);

    const pk = createPublicKey({
      key: keyBuffer,
      format: KEY_FORMAT_OPTIONS.format,
      type: KEY_FORMAT_OPTIONS.type,
    });

    return new Header(pk, parsed.pn, parsed.n);
  }
}

export { Header };
