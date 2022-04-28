package cryptoj.examples.simple;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate xPub
 */
public class SimpleExample2XPub {

    public static void main(String[] args) throws CryptoJException {
        String xPub = CryptoJ.generateXPub(
                Network.BITCOIN_MAINNET,
                AddressType.P2WPKH_NATIVE_SEGWIT,
                "cradle ask dentist asthma glow relax fall spatial circle credit mind gap"
        );
        System.out.println("xPub = " + xPub);
    }

}
