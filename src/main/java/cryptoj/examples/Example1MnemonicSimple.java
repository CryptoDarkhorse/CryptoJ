package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate random mnemonic
 */
public class Example1MnemonicSimple {

    public static void main(String[] args) throws CryptoJException {
        System.out.println("Random mnemonic = " + CryptoJ.generateMnemonic(12));
    }

}
