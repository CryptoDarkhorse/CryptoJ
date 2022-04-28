package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Sign a message, verify signed message
 */
public class Example_2_SignAndVerifyMessage {

    public static void main(String[] args) throws CryptoJException {

        Network network = Network.BITCOIN_MAINNET;
        AddressType addressType = AddressType.P2WPKH_NATIVE_SEGWIT;
        String mnemonic = CryptoJ.generateMnemonic(12);
        String xPub = CryptoJ.generateXPub(network, addressType, mnemonic);
        int derivationIndex = 0;
        String address = CryptoJ.generateAddress(network, addressType, xPub, derivationIndex);
        String privateKey = CryptoJ.generatePrivateKey(network, addressType, mnemonic, derivationIndex);

        System.out.println("Network = " + network.getName());
        System.out.println("AddressType = " + addressType.getName());
        System.out.println("Mnemonic = " + mnemonic);
        System.out.println("xPub = " + xPub);
        System.out.println("derivationIndex = " + derivationIndex);
        System.out.println("address = " + address);
        System.out.println("privateKey = " + privateKey);

        System.out.println("\n\n");

        String rawMessage = "Hello world, this is CryptoJ!";
        System.out.println("Raw message = " + rawMessage);

        String signedMessage = CryptoJ.signMessage(
                rawMessage,
                privateKey
        );
        System.out.println("Signed message = " + signedMessage);

        String verifiedMessage = CryptoJ.verifyMessage(
                signedMessage,
                address
        );
        System.out.println("Verified message (should be the same as raw message) = " + verifiedMessage);

        System.out.println("Signed message is verified: " + verifiedMessage.equals(rawMessage));

    }

}
