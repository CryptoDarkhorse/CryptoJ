package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate 100 random valid mnemonics with random length
 */
public class Example1Mnemonic {

    public static void main(String[] args) throws CryptoJException {
        for (int i = 0; i < 100; i++) {
            int mnemonicLength = getRandomMnemonicLength();
            System.out.println("Mnemonic no. " + i + ": " + CryptoJ.generateMnemonic(mnemonicLength));
        }
    }

    public static int getRandomNumber(int min, int max) {
        return (int) ((Math.random() * (max - min)) + min);
    }

    public static int getRandomMnemonicLength() {
        int length = getRandomNumber(12, 24);
        while (length % 3 != 0) {
            length = getRandomNumber(12, 24);
        }
        return length;
    }

}
