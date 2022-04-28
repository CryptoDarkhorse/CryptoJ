package cryptoj.examples.simple;

import cryptoj.CryptoJ;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate random mnemonic
 */
public class SimpleExample1Mnemonic {

    public static void main(String[] args) throws CryptoJException {
        System.out.println("Random mnemonic = " + CryptoJ.generateMnemonic(12));
    }

}
