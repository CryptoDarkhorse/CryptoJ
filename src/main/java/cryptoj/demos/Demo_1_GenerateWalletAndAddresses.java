package cryptoj.demos;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate wallet and address for receiving coins (and their private keys)
 */
public class Demo_1_GenerateWalletAndAddresses {

    public static void main(String[] args) throws CryptoJException {

        Network network = Network.BITCOIN_MAINNET;
        AddressType addressType = AddressType.P2WPKH_NATIVE_SEGWIT;

        String mnemonic = CryptoJ.generateMnemonic(12);
        System.out.println("Your wallet mnemonic (seed) = " + mnemonic);

        String xPub = CryptoJ.generateXPub(network, addressType, mnemonic);
        System.out.println("Your wallet xPub = " + xPub);

        for (int derivationIndex = 0; derivationIndex < 10; derivationIndex++) {
            String address = CryptoJ.generateAddress(network, addressType, xPub, derivationIndex);
            String privateKey = CryptoJ.generatePrivateKey(network, addressType, mnemonic, derivationIndex);
            System.out.println("Your wallet address (on index " + derivationIndex + ") = " + address + " ; PrivateKey = " + privateKey);
        }

    }

}
