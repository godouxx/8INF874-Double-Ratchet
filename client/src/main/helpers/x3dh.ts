import {
  generateKeyPairSync,
  diffieHellman,
  hkdfSync,
  createSign,
  createVerify,
  KeyObject,
} from 'crypto';

const DH_TYPE = 'prime256v1';

function concat(...buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

// Génère une paire de clés ECDH
export function generateKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: DH_TYPE,
  });
  return { publicKey, privateKey };
}

// X3DH côté initiateur
export function x3dhInitiator(
  ikLocal: KeyObject,
  ekLocal: KeyObject,
  ikRemote: KeyObject,
  spkRemote: KeyObject,
  opkRemote?: KeyObject
): Buffer  {
  const dh1 = diffieHellman({ privateKey: ikLocal, publicKey: spkRemote });
  const dh2 = diffieHellman({ privateKey: ekLocal, publicKey: ikRemote });
  const dh3 = diffieHellman({ privateKey: ekLocal, publicKey: spkRemote });
  const dh4 = opkRemote ? diffieHellman({ privateKey: ekLocal, publicKey: opkRemote }) : Buffer.alloc(0);

  const sharedSecret = concat(dh1, dh2, dh3, dh4);
  const masterKeyArrayBuffer = hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('X3DH'), 32);
  const masterKey = Buffer.from(masterKeyArrayBuffer);

  return masterKey;
}

// X3DH côté répondeur
export function x3dhResponder(
  ikLocal: KeyObject,
  spkLocal: KeyObject,
  ekRemote: KeyObject,
  ikRemote: KeyObject,
  opkLocal?: KeyObject
): Buffer {
  const dh1 = diffieHellman({ privateKey: spkLocal, publicKey: ikRemote });
  const dh2 = diffieHellman({ privateKey: ikLocal, publicKey: ekRemote });
  const dh3 = diffieHellman({ privateKey: spkLocal, publicKey: ekRemote });
  const dh4 = opkLocal ? diffieHellman({ privateKey: opkLocal, publicKey: ekRemote }) : Buffer.alloc(0);

  const sharedSecret = concat(dh1, dh2, dh3, dh4);
  const masterKeyArrayBuffer = hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('X3DH'), 32);
  const masterKey = Buffer.from(masterKeyArrayBuffer);

  return masterKey;
}

// Génère une SPK et la signe avec la clé d'identité
export function generateSignedPreKey(identityPrivateKey: KeyObject): {
  spk: { publicKey: KeyObject; privateKey: KeyObject };
  signature: Buffer;
} {
  const spk = generateKeyPair();

  const signObj = createSign('sha256');
  signObj.update(spk.publicKey.export({ format: 'der', type: 'spki' }));
  signObj.end();

  const signature = signObj.sign(identityPrivateKey);
  return { spk, signature };
}