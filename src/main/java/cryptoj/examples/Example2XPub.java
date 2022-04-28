package cryptoj.examples;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate all possible xPubs (for all networks and address types) from one random mnemonic.
 */
public class Example2XPub {

    public static void main(String[] args) throws CryptoJException {
        String mnemonic = CryptoJ.generateMnemonic(Example1Mnemonic.getRandomMnemonicLength());
        System.out.println("MNEMONIC = " + mnemonic + "\n\n");
        for (Network network : Network.values()) {
            for (AddressType addressType : AddressType.values()) {
                if (addressType == AddressType.P2SH_PAY_TO_SCRIPT_HASH) continue; // it's not possible to generate xPub from this address type, therefore let's skip thisone
                String xPub = CryptoJ.generateXPub(network, addressType, mnemonic);
                System.out.println("Network = " + network.getName());
                System.out.println("Address type = " + addressType.getName());
                System.out.println("xPub = " + xPub);
                System.out.println("\n");
            }
        }
    }

}
