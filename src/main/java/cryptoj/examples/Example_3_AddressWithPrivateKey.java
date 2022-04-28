package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate address for receiving coins (plus its private key)
 */
public class Example_3_AddressWithPrivateKey {

    public static void main(String[] args) throws CryptoJException {

        Network network = Network.BITCOIN_MAINNET;
        AddressType addressType = AddressType.P2WPKH_NATIVE_SEGWIT;
        String mnemonic = "talk fit neglect emotion elder sadness garbage smile twelve logic goat margin";
        String xPub = "zpub6stiPqYq3eSVU3bneZs6BCEe2H6zY133RZfxnuNu5ZmwFPQifTsnMmNs6QPKk9e1FRAffMUAVnAsv8YAFjDib4oxvrSqJNCZTwrUKS5L1HD";
        int derivationIndex = 0; // first address of the xpub

        String address = CryptoJ.generateAddress(
                network,
                addressType,
                xPub,
                derivationIndex
        );

        String privateKey = CryptoJ.generatePrivateKey(
                network,
                addressType,
                mnemonic,
                derivationIndex
        );

        System.out.println("Address = " + address + " ; PrivateKey = " + privateKey);
    }

}
