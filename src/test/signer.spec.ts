import { hashMessage, hashTypedData, parseEther } from 'viem';
import * as viem from 'viem';
import { KmsSigner } from '../';
import * as utils from '../utils/kms-utils';

describe('Viem KMS Signer', () => {
  let signer: KmsSigner;
  let credentials: any;

  beforeEach(() => {
    credentials = {
      keyId: 'kms-key-id',
    };

    signer = new KmsSigner(credentials);
  });

  it('Should be defined', () => {
    expect(signer).toBeDefined();
  });

  describe('Get Address', () => {
    it('Should get eth address from kms private key', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );
      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);

      const addr = await signer.getAddress();

      expect(addr).toBe(expectedAddress);
      expect(utils.getPublicKey).toHaveBeenCalledWith(credentials);
      expect(utils.getEthereumAddress).toHaveBeenCalledWith(
        Buffer.from(pubKey),
      );
    });

    it('Should cache eth address in memory', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );

      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);

      let addr = await signer.getAddress();

      expect(addr).toBe(expectedAddress);

      addr = await signer.getAddress();

      expect(addr).toBe(expectedAddress);
      expect(utils.getPublicKey).toHaveBeenCalledTimes(2);
      expect(utils.getEthereumAddress).toHaveBeenCalledTimes(2);
    });
  });

  describe('Get Account', () => {
    it('Should return viem account', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );

      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);

      const account = await signer.getAccount();

      expect(account.address).toBe(expectedAddress);
      expect(account.signMessage).toBeDefined();
      expect(account.signTransaction).toBeDefined();
      expect(account.signTypedData).toBeDefined();
    });
  });

  describe('Account - Sign Message', () => {
    it('Should sign message', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const message = 'Hello World';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );

      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);
      jest
        .spyOn(utils, 'signDigestHex')
        .mockImplementation(() => '0xsig' as any);

      const account = await signer.getAccount();
      const sig = await account.signMessage({ message });

      expect(sig).toBe('0xsig');
      expect(utils.signDigestHex).toHaveBeenCalledWith(
        hashMessage(message),
        credentials,
        expectedAddress,
      );
    });
  });

  describe('Account - Sign Transaction', () => {
    it('Should sign message', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );
      const tx: any = {
        to: expectedAddress,
        value: parseEther('0.1'),
      };

      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);
      jest
        .spyOn(utils, 'signTransaction')
        .mockImplementation(() => '0xsig' as any);

      const account = await signer.getAccount();
      const sig = await account.signTransaction(tx);

      expect(sig).toBe('0xsig');
      expect(utils.signTransaction).toHaveBeenCalledWith(
        tx,
        credentials,
        expectedAddress,
      );
    });
  });

  describe('Account - Sign Typed Data', () => {
    it('Should sign message', async () => {
      const expectedAddress = '0xe94e130546485b928c9c9b9a5e69eb787172952e';
      const pubKey = Uint8Array.from(
        Buffer.from(
          'eafb54d808f29324e8bb65ac7b8e71531e67473dee2d48724624decc58c268a4',
          'hex',
        ),
      );
      const data: any = {
        to: expectedAddress,
        value: parseEther('0.1'),
      };

      jest.spyOn(utils, 'getPublicKey').mockImplementation(() => {
        return {
          PublicKey: pubKey,
        } as any;
      });
      jest
        .spyOn(utils, 'getEthereumAddress')
        .mockImplementation(() => expectedAddress);
      jest
        .spyOn(utils, 'signDigestHex')
        .mockImplementation(() => '0xsig' as any);
      jest
        .spyOn(viem, 'hashTypedData')
        .mockImplementation(() => '0xsig' as any);

      const account = await signer.getAccount();
      const sig = await account.signTypedData(data);

      expect(sig).toBe('0xsig');
      expect(utils.signDigestHex).toHaveBeenCalledWith(
        hashTypedData(data),
        credentials,
        expectedAddress,
      );
    });
  });
});
