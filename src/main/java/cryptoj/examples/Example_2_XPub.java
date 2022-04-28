package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate xPub
 */
public class Example_2_XPub {

    public static void main(String[] args) throws CryptoJException {
        String xPub = CryptoJ.generateXPub(
                Network.BITCOIN_MAINNET,
                AddressType.P2WPKH_NATIVE_SEGWIT,
                "talk fit neglect emotion elder sadness garbage smile twelve logic goat margin"
        );
        System.out.println("xPub = " + xPub);
        // the result might look like for example "zpub6stiPqYq3eSVU3bneZs6BCEe2H6zY133RZfxnuNu5ZmwFPQifTsnMmNs6QPKk9e1FRAffMUAVnAsv8YAFjDib4oxvrSqJNCZTwrUKS5L1HD"
    }

}
