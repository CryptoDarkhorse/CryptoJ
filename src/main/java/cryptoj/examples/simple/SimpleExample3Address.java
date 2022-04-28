package cryptoj.examples.simple;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;

/**
 * Generate address for receiving coins
 */
public class SimpleExample3Address {

    public static void main(String[] args) throws CryptoJException {
        String address = CryptoJ.generateAddress(
                Network.BITCOIN_MAINNET,
                AddressType.P2WPKH_NATIVE_SEGWIT,
                "zpub6t8WjYtDA4vBhFu8E2ziVCqmBURt8GWmqMZhqsQvCS8ogQ2aQedRufTpq9J2xhGyLNYHcj1vi7QQLNFYEP2XHcXstV3b5jmjZdrrrb4p4wD",
                0
        );
        System.out.println("Address = " + address);
    }

}
