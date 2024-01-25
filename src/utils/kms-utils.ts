import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { AwsKmsSignerCredentials } from '..';
import * as asn1 from 'asn1.js';
import { keccak256 } from 'viem';

const EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(
    this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
    this.key('pubKey').bitstr(),
  );
});

export async function getPublicKey(kmsCredentials: AwsKmsSignerCredentials) {
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
