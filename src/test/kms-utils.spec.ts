import { BN } from 'bn.js';
import {
  getEthereumAddress,
  getPublicKey,
  determineCorrectV,
  findEthereumSig,
} from '../utils/kms-utils';

jest.mock('@aws-sdk/client-kms', () => {
  class KMSClient {
    async send(command) {
      return { PublicKey: 'pubkey', command };
    }
  }

  class GetPublicKeyCommand {
    input: any;

    constructor(input) {
      this.input = input;
    }
  }

  class SignCommand {}

  return { KMSClient, GetPublicKeyCommand, SignCommand };
});

describe('KMS Utils', () => {
  let credentials: any = { keyId: 'key-id' };

  describe('Get Public Key', () => {
    it('Should send request to AWS KMS server', async () => {
      class GetPublicKeyCommand {
        input: any;

        constructor(input) {
          this.input = input;
        }
      }

      const command = new GetPublicKeyCommand({ KeyId: credentials.keyId });

      const res = await getPublicKey(credentials);
      expect(JSON.stringify(res)).toBe(
        JSON.stringify({
          PublicKey: 'pubkey',
          command,
        }),
      );
    });
  });

  describe('Get Ethereum Address', () => {
    it('Should return correct address', () => {
      expect(
        getEthereumAddress(
          Buffer.from(
            '3056301006072a8648ce3d020106052b8104000a03420004f2de8ae7a9f594fb0d399abfb58639f43fb80960a1ed7c6e257c11e764d4759e1773a2c7ec7b913bec5d0e3a12bd7acd199f62e86de3f83b35bf6749fc1144ba',
            'hex',
          ),
        ),
      ).toBe('0xe94e130546485b928c9c9b9a5e69eb787172952e');
    });
  });

  // describe('Request KMS Signature', () => {
  //   it('Should get kms sig', async () => {
  //     const plaintext = Buffer.from(
  //       '7403bcdb90a1140e737526530bb5bc5d02f9b7c34228a44dfede3822829dd9fe',
  //       'hex',
  //     );

  //     jest.spyOn(utils, 'sign').mockImplementation(async () => {
  //       return {
  //         Signature: Uint8Array.from(
  //           Buffer.from(
  //             '304502203f25afdb7ed67094101cd71109261886db9abbf1ba20cc53aec20ba01c2e6baa022100ab0de6d40f8960c252fc6f21e35e8369126fb19033f10953c42a61766635df82',
  //             'hex',
  //           ),
  //         ),
  //       } as any;
  //     });
  //     jest
  //       .spyOn(utils, 'findEthereumSig')
  //       .mockImplementation(() => '0xsig' as any);

  //     await requestKmsSignature(plaintext, credentials);
  //   });
  // });

  describe('findEthereumSig', () => {
    it('should work correctly', () => {
      const sampleSignature = Buffer.from(
        '304502203f25afdb7ed67094101cd71109261886db9abbf1ba20cc53aec20ba01c2e6baa022100ab0de6d40f8960c252fc6f21e35e8369126fb19033f10953c42a61766635df82',
        'hex',
      );
      expect(JSON.stringify(findEthereumSig(sampleSignature))).toBe(
        '{"r":"3f25afdb7ed67094101cd71109261886db9abbf1ba20cc53aec20ba01c2e6baa","s":"54f2192bf0769f3dad0390de1ca17c95a83f2b567b5796e7fba7fd166a0061bf"}',
      );
    });
  });

  describe('Determine Correct V', () => {
    it('should get correct V if it is 28', async () => {
      const sampleMsg = Buffer.from(
        'a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2',
        'hex',
      );
      const sampleR = new BN(
        'fa754063b93a288b9a96883fc365efb9aee7ecaf632009baa04fe429e706d50e',
        16,
      );
      const sampleS = new BN(
        '6a8971b06cd37b3da4ad04bb1298fda152a41e5c1104fd5d974d5c0a060a5e62',
        16,
      );
      const expectedAddr = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      expect(
        await determineCorrectV(sampleMsg, sampleR, sampleS, expectedAddr),
      ).toBe(28);
    });

    it('should get correct V if it is 27', async () => {
      const sampleMsg = Buffer.from(
        'a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2',
        'hex',
      );
      const sampleR = new BN(
        '904d320777ceae0232282cbf6da3809a678541cdef7f4f3328242641ceecb0dc',
        16,
      );
      const sampleS = new BN(
        '5b7f7afe18221049a1e176a89a60b6c10df8c0e838edb9b2f11ae1fb50a28271',
        16,
      );
      const expectedAddr = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      expect(
        await determineCorrectV(sampleMsg, sampleR, sampleS, expectedAddr),
      ).toBe(27);
    });
  });
});
