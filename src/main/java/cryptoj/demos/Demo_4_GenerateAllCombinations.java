package cryptoj.demos;

import cryptoj.CryptoJ;
import cryptoj.enums.AddressType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;
import cryptoj.tools.StringTools;

/**
 * Generate all combinations of networks, address types, example mnemonic, wallets, their addresses and private keys
 */
public class Demo_4_GenerateAllCombinations {

    public static void main(String[] args) throws CryptoJException {
        for (Network network : Network.values()) {
            for (AddressType addressType : AddressType.values()) {
                if (addressType == AddressType.P2SH_PAY_TO_SCRIPT_HASH) {
                    continue;
                }
                String passphrase = StringTools
                        .generateRandomString(
                                12,
                                StringTools.ALPHANUMERIC_CASE_SENSITIVE_ARRAY
                        ); // generated random passphrase
                String mnemonic = CryptoJ.generateMnemonic(
                        12,
                        passphrase // passphrase used when generating mnemonic
                );
                String xPub = CryptoJ.generateXPub(
                        network,
                        addressType,
                        mnemonic,
                        passphrase // passphrase used when generating xpub
                );
                System.out.println("network = " + network.getName());
                System.out.println("addressType = " + addressType.getName());
                System.out.println("passphrase = " + passphrase);
                System.out.println("mnemonic = " + mnemonic);
                System.out.println("xPub = " + xPub);
                for (int derivationIndex = 0; derivationIndex < 10; derivationIndex++) {
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
                            passphrase, // passphrase used when generating private key
                            derivationIndex
                    );
                    System.out.println("Index " + derivationIndex + ": Address = " + address + " ; PrivateKey = " + privateKey);
                    // signature verification /BEGINS/ // check if our address+privKey pair match together
                    String rawMessage = StringTools.generateRandomString(
                            12,
                            StringTools.ALPHANUMERIC_CASE_SENSITIVE_ARRAY
                    ); // random raw message
                    String signature = CryptoJ.signMessage(
                            network,
                            rawMessage,
                            privateKey
                    ); // sign message with privKey
                    boolean isVerified = CryptoJ.verifyMessage(
                            network,
                            rawMessage,
                            signature,
                            address
                    ); // verify signature with address, this will let us know if our address+privKey pair is correct together
                    if (isVerified == false) {
                        throw new CryptoJException("Signature verification has failed.");
                    }
                    // signature verification /ENDS/ // check if our address+privKey pair match together
                    // encryption/decryption of a message BEGINS
                    String encryptedMessage = CryptoJ.encryptMessage(
                            rawMessage,
                            CryptoJ.getPublicKey(network, privateKey)
                    );
                    String decryptedMessage = CryptoJ.decryptMessage(
                            network,
                            encryptedMessage,
                            privateKey
                    );
                    if (decryptedMessage.equals(rawMessage) == false) { // compare if decrypted equals to original raw
                        throw new CryptoJException("Encryption/Decryption verification has failed.");
                    }
                    // encryption/decryption of a message ENDS
                }
                System.out.println("\n\n");
            }
        }
    }

}
