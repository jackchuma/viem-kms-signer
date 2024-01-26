import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
  SignCommandInput,
  GetPublicKeyCommandOutput,
  SignCommandOutput,
} from '@aws-sdk/client-kms';
import { AwsKmsSignerCredentials } from '..';
import * as asn1 from 'asn1.js';
import {
  Signature,
  TransactionSerializable,
  keccak256,
  recoverAddress,
  serializeTransaction,
  signatureToHex,
} from 'viem';
import BN from 'bn.js';

const EcdsaSigAsnParse: {
  decode: (asnStringBuffer: Buffer, format: 'der') => { r: BN; s: BN };
} = asn1.define('EcdsaSig', function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key('r').int(), this.key('s').int());
});
const EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(
    this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
    this.key('pubKey').bitstr(),
  );
});

export async function getPublicKey(
  kmsCredentials: AwsKmsSignerCredentials,
): Promise<GetPublicKeyCommandOutput> {
  const kms = new KMSClient(kmsCredentials);
  const input = {
    KeyId: kmsCredentials.keyId,
  };
  const command = new GetPublicKeyCommand(input);
  return await kms.send(command);
}

export function getEthereumAddress(publicKey: Buffer): `0x${string}` {
  const res = EcdsaPubKey.decode(publicKey, 'der');
  const pubKeyBuffer = res.pubKey.data.slice(1);
  const address = keccak256(pubKeyBuffer);
  return `0x${address.slice(-40)}`;
}

export async function requestKmsSignature(
  plaintext: Buffer,
  kmsCredentials: AwsKmsSignerCredentials,
): Promise<{ r: BN; s: BN }> {
  const signature = await sign(plaintext, kmsCredentials);

  if (!signature || signature.Signature === undefined) {
    throw new Error(`AWS KMS call failed: ${signature}`);
  }
  return findEthereumSig(Buffer.from(signature.Signature));
}

async function sign(
  digest: Buffer,
  kmsCredentials: AwsKmsSignerCredentials,
): Promise<SignCommandOutput> {
  const kms = new KMSClient(kmsCredentials);
  const input: SignCommandInput = {
    // key id or 'Alias/<alias>'
    KeyId: kmsCredentials.keyId,
    Message: digest,
    // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
    SigningAlgorithm: 'ECDSA_SHA_256',
    MessageType: 'DIGEST',
  };
  const command = new SignCommand(input);
  return await kms.send(command);
}

export function findEthereumSig(signature: Buffer): { r: BN; s: BN } {
  const decoded = EcdsaSigAsnParse.decode(signature, 'der');
  const { r, s } = decoded;

  const secp256k1N = new BN(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    16,
  ); // max value on the curve
  const secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
  // Because of EIP-2 not all elliptic curve signatures are accepted
  // the value of s needs to be SMALLER than half of the curve
  // i.e. we need to flip s if it's greater than half of the curve
  // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
  return { r, s: s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s };
}

export async function determineCorrectV(
  msg: Buffer,
  r: BN,
  s: BN,
  expectedEthAddr: string,
): Promise<number> {
  // This is the wrapper function to find the right v value
  // There are two matching signatues on the elliptic curve
  // we need to find the one that matches to our public key
  // it can be v = 27 or v = 28
  let v = 27;
  const pubKey = await recoverPubKeyFromSig(msg, r, s, v);
  if (pubKey.toLowerCase() !== expectedEthAddr.toLowerCase()) {
    // if the pub key for v = 27 does not match
    // it has to be v = 28
    v = 28;
  }
  return v;
}

function recoverPubKeyFromSig(
  msg: Buffer,
  r: BN,
  s: BN,
  v: number,
): Promise<`0x${string}`> {
  return recoverAddress({
    hash: `0x${msg.toString('hex')}`,
    signature: signatureToHex({
      r: `0x${r.toString('hex')}`,
      s: `0x${s.toString('hex')}`,
      v: BigInt(v),
    }),
  });
}

export async function signDigestHex(
  digestString: string,
  kmsCredentials: AwsKmsSignerCredentials,
  address: `0x${string}`,
): Promise<`0x${string}`> {
  return signatureToHex(
    await _signDigest(digestString, kmsCredentials, address),
  );
}

async function _signDigest(
  digestString: string,
  kmsCredentials: AwsKmsSignerCredentials,
  address: `0x${string}`,
): Promise<Signature> {
  const digestBuffer = Buffer.from(digestString.slice(2), 'hex');
  const sig = await requestKmsSignature(digestBuffer, kmsCredentials);
  const v = await determineCorrectV(digestBuffer, sig.r, sig.s, address);
  return {
    r: `0x${sig.r.toString('hex')}`,
    s: `0x${sig.s.toString('hex')}`,
    v: BigInt(v),
  };
}

export async function signTransaction(
  transaction: TransactionSerializable,
  kmsCredentials: AwsKmsSignerCredentials,
  address: `0x${string}`,
): Promise<`0x${string}`> {
  const serializedTx = serializeTransaction(transaction);
  const transactionSignature = await _signDigest(
    keccak256(serializedTx),
    kmsCredentials,
    address,
  );
  return serializeTransaction(transaction, transactionSignature);
}
