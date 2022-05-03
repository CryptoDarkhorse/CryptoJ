package cryptoj.demos;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate all combinations of networks, address types, example mnemonic, wallets, their addresses and private keys
 */
public class Demo_3_EncryptAndDecryptMessage {

    public static void main(String[] args) throws CryptoJException {

        Network network = Network.BITCOIN_MAINNET;
        AddressType addressType = AddressType.P2WPKH_NATIVE_SEGWIT;
        String mnemonic = CryptoJ.generateMnemonic(12);
        String xPub = CryptoJ.generateXPub(network, addressType, mnemonic);
        int derivationIndex = 0;
        String address = CryptoJ.generateAddress(network, addressType, xPub, derivationIndex);
        String privateKey = CryptoJ.generatePrivateKey(network, addressType, mnemonic, derivationIndex);
        String publicKey = CryptoJ.getPublicKey(network, privateKey);

        System.out.println("Network = " + network.getName());
        System.out.println("AddressType = " + addressType.getName());
        System.out.println("Mnemonic = " + mnemonic);
        System.out.println("xPub = " + xPub);
        System.out.println("derivationIndex = " + derivationIndex);
        System.out.println("address = " + address);
        System.out.println("privateKey = " + privateKey);
        System.out.println("publicKey = " + publicKey);

        System.out.println("\n\n");

        String rawMessage = "Hello world, this is CryptoJ!";
        System.out.println("rawMessage = " + rawMessage);

        String encryptedMessage = CryptoJ.encryptMessage(rawMessage, publicKey);
        System.out.println("encryptedMessage = " + encryptedMessage);

        String decryptedMessage = CryptoJ.decryptMessage(network, encryptedMessage, privateKey);
        System.out.println("decryptedMessage = " + decryptedMessage);

        System.out.println("decryptedMessage.equals(rawMessage) = " + decryptedMessage.equals(rawMessage));

    }

}
