import { KeyObject } from "crypto";

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

  toBuffer(): Buffer {
    return Buffer.concat([
      this.pk.export(KEY_FORMAT_OPTIONS),
      Buffer.from(this.pn.toString()),
      Buffer.from(this.n.toString()),
    ]);
  }

  toJson(): object {
    return {
      pk: this.pk,
      pn: this.pn,
      n: this.n,
    };
  }
}

export { Header };
