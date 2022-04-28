package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate random mnemonic
 */
public class Example_1_Mnemonic {

    public static void main(String[] args) throws CryptoJException {
        System.out.println("Random mnemonic = " + CryptoJ.generateMnemonic(12));
        // the result might look like for example "talk fit neglect emotion elder sadness garbage smile twelve logic goat margin"
    }

}
