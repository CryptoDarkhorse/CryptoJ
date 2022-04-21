package org.example.cryptotoolprojectdescription;

import org.example.cryptotoolprojectdescription.enums.AddressType;
import org.example.cryptotoolprojectdescription.enums.NetType;
import org.example.cryptotoolprojectdescription.enums.Network;
import org.example.cryptotoolprojectdescription.exceptions.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test class for CrypoJ library
 * All test cases are made using "Mnemonic Code Converter"(https://iancoleman.io/bip39/)
 */
public class TestMain {
    @Test
    @DisplayName("Testing mnemonic generation & validation")
    void testMnemonic() {
        try {
            String generated = CryptoJ.generateMnemonic(12);
            assertTrue(CryptoJ.isMnemonicValid(generated));

            String validMnemonic = "clap shove riot taxi vessel achieve echo swift ripple blush rate census sick exit dry make adult swing";
            assertTrue(CryptoJ.isMnemonicValid(validMnemonic));
        } catch (CryptoException e) {
            e.printStackTrace();
            assertTrue(false, "Invalid CryptoException catched");
        }
    }

    @Test
    @DisplayName("Key derivation test")
    void testHDKey() {
        // Generate deterministic seed
        String mnemonic = "floor earn cube small wolf elevator leaf duty deposit renew balcony chat";

        String xpubKey = "";

        try {
            /**
             * Test function generateXPub
             */

            // Bitcoin mainnet
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "xpub6FMTbmnDJwazR9LAnoTn8PwZWLHzJd7jLBng6cqCAaEhp7ZMLAf1usWraE3VVqtNphkPMf6YoRDzPuwLATY362uS4FGZfdDbfDTbFH1sdwz");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6tvnwHiSB6q4jc7bXkJTgVTTisdsn3zMdUvyEeUCA86PVhsj1JcS9kAZXEVbNBuWCpkk7KQf6HE4b9x7mX9kp8vGAJPRhGhjgg9byG9xNvo");

            // Bitcoin regtest
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN_REGTEST, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN_REGTEST, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "vpub5bCa8otgRnQ7Xb7qhGFEkGwRjDz82Qfj3x9e5c2r5Xqpobz6MPaf3Zs4M6uNartStzWAuaZNZFdM3TThRTHKdN1NXbGSnXwqRgpS1kxSjtL");

            // Bitcoin testnet
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN_TESTNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN, NetType.BITCOIN_TESTNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "vpub5bCa8otgRnQ7Xb7qhGFEkGwRjDz82Qfj3x9e5c2r5Xqpobz6MPaf3Zs4M6uNartStzWAuaZNZFdM3TThRTHKdN1NXbGSnXwqRgpS1kxSjtL");

            // Ethereum
            xpubKey = CryptoJ.generateXPub(Network.ETHEREUM, NetType.ETHEREUM, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "xpub6E1AXXK6MkDEsbNhCefGmfZjkxyzKGiA4hHnW6L8ZmfEwP3cNdKe264ApHFo2W4fp2nwEsNxyyfQtiyg3dXtXATh8yagyJ1i5HNv5c1C2zv");
            xpubKey = CryptoJ.generateXPub(Network.ETHEREUM, NetType.ETHEREUM, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6tUrF813QV9gcPERodUnGLBQdRP2wa1CBKf1XV7zesBV2hkba3FyB8ExZ1Ujngmc12FpfaA2qQJGc5c7bNYovLm9AyVrsn72x2Gjuc1f6BG");

            // Litecoin mainnet
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN, NetType.LITECOIN, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "Ltub2bQDUX7WAWbe8KsoQp7rwbbJ5dwtzGUyKmu9U9pLyGV8AYtALWfTwAsestHyxwSMsHjmG4JwSRGjQUsZcqt4AiSGAdbF5rZSKQQrCDh6nqj");
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN, NetType.LITECOIN, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6toHVn6wiReBoYxhWj3BdpW2wZ4M3G17aRv4DyP4XmMENkVPZxBpDTVfPXfzyepCiDK4J83tj6hGCEzHJTxvoedykoiyy5XDcFWukSfZajk");

            // Litecoin testnet
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN, NetType.LITECOIN_TESTNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN, NetType.LITECOIN_TESTNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "tpubDFEjGP4CSRSXVygvpAoaNNToQHNfu39nRonNzwsmBTMUf6HFvvksS8rAdYuL7B9XWBGh27GN1gAVWDBSFhxb7GpsKsQbdtF3Z6Y8YspuBtG");

            /**
             * Test function isXPubValid
             */
            Network network = Network.BITCOIN;
            NetType netType = NetType.BITCOIN;
            AddressType addrType = AddressType.P2PKH_LEGACY;
            boolean isValid = false;

            // Test cases from BIP32
            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "zpub6r5kw6MCdkevJCZ5XN7crPMKLKJhmh4Dk8eZPDXXwhaoSBDixyrJWu7Juwd5YdjdqZ15j1LCuGxQvZ6NVayNbLe5rvMUuHHs1JE8hxvimPn");
            assertTrue(isValid);

            // invalid xpubKeys
            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm");
            assertFalse(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn");
            assertFalse(isValid);

            isValid = CryptoJ.isXPubValid(network, netType, addrType,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4");
            assertFalse(isValid);
        } catch (CryptoException e) {
            e.printStackTrace();
            assertTrue(false, "Invalid CryptoException catched");
        }
    }

    @Test
    @DisplayName("Test account's private key & address")
    void testAccountInfo() {
        // Generate deterministic seed
        String mnemonic = "floor earn cube small wolf elevator leaf duty deposit renew balcony chat";

        Network network = Network.BITCOIN;
        NetType netType = NetType.BITCOIN_TESTNET;
        AddressType addrType = AddressType.P2WPKH_NATIVE_SEGWIT;

        String address;
        String xpub;
        String prvKey = "";

        try {
            network = Network.BITCOIN;
            netType = NetType.BITCOIN;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 0);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 0);
            assertEquals(address, "1N2cRhBBPACXzwLN5iMbTepyeknAsjSP4W");
            assertEquals(prvKey, "L3zJJbXrwr7Gk5Jbp7icqXgVYmhhyBidwnoA5axHRffjKqfZc4Gq");

            network = Network.BITCOIN;
            netType = NetType.BITCOIN;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 3);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 3);
            assertEquals(address, "bc1qqkhc9mjkw0rr6n5xechhnvj2lldnd8g7nc3smd");
            assertEquals(prvKey, "Kx7rDkP5ESZnhXVjBSUsRP3LChNw3VArUV2QMBuiZkNW7cqJqReC");

            network = Network.BITCOIN;
            netType = NetType.BITCOIN_TESTNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 7);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 7);
            assertEquals(address, "n3dJrXNo4ujsbDj7Qt4KGEHd4Sog4eg1rM");
            assertEquals(prvKey, "cVwwGkHKb49YnUd2MKRgGXkbNi94U3BfFXTKxNDhwt2xYg4KGCaa");

            network = Network.BITCOIN;
            netType = NetType.BITCOIN_TESTNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 5);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 5);
            assertEquals(address, "tb1q8n8cgzvje429hgygc64c3u0w77pyj7cj9fjfln");
            assertEquals(prvKey, "cV6qvG8sAzkVLjJ8oGfvLwBsdyXuKWryTcg5BYN1X4FGFF4Bfcfz");

            network = Network.BITCOIN;
            netType = NetType.BITCOIN_REGTEST;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 2);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 2);
            assertEquals(address, "n31cruGhMj8gFJWjUNk2HdNjqw3gCSABPa");
            assertEquals(prvKey, "cQiQ1qtkzRc83ES9zn7sAJuL7LQki6qwjCsmpKX49Y63wrQyctkR");

            network = Network.BITCOIN;
            netType = NetType.BITCOIN_REGTEST;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 1);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 1);
            assertEquals(address, "bcrt1qy9tr0sl96y4nt2y6axaq7ca5ajm7zma9caacuf");
            assertEquals(prvKey, "cQQ9AaCJLM79hmGiRpuik72gn3mgcGYgEQeCRnSaCgKhzhWj6gHp");

            network = Network.ETHEREUM;
            netType = NetType.ETHEREUM;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 4);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 4);
            assertEquals(address, "0xCea857A7b2F1efA2666D0915Fa66808bd4a5E7BB");
            assertEquals(prvKey, "0x23a3d50abb6724676f34faaba2d3d0a1fb72b00a453c22d411813c1c46c01b81");

            network = Network.ETHEREUM;
            netType = NetType.ETHEREUM;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 1);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 1);
            assertEquals(address, "bc1qlwl8qdrk26q839exs54yu2v85mls2qe9fp4ad7");
            assertEquals(prvKey, "0x4fa2c5184231d2f20a9a9e6e933758cfdcebee5f5546fc8dd72ac9461ed5ffaf");

            network = Network.LITECOIN;
            netType = NetType.LITECOIN;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 9);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 9);
            assertEquals(address, "LMd632NKqw44qKmqUEK6pt8nYfTsG7xQC8");
            assertEquals(prvKey, "T5H7xHs9XU5uAHQaSySZysPFMGhMgGa5pQkKDv7DLHVUK8wWXAEx");

            network = Network.LITECOIN;
            netType = NetType.LITECOIN;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 5);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 5);
            assertEquals(address, "ltc1qdx0stttmzlexzaresv2py8s66776plgxx4w4z4");
            assertEquals(prvKey, "T54cuK5Hd4BVTStMiw9e6oqkRsasws3pBfbJCwaQeVD74Ky5TKiy");

            network = Network.LITECOIN;
            netType = NetType.LITECOIN_TESTNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 8);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 8);
            assertEquals(address, "mkmNPH2xWmn422UotCNskED9QKAvnGvcLA");
            assertEquals(prvKey, "cVdsBsrPLZsEtLxh8TQfjmdaSXDG3632zuHYBNDRDYbSvwQxwApi");

            network = Network.LITECOIN;
            netType = NetType.LITECOIN_TESTNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, netType, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivKey(network, netType, addrType, mnemonic, 7);
            address = CryptoJ.generateAddress(network, netType, addrType, xpub, 7);
            assertEquals(address, "litecointestnet1qjjrmmenxx7ca7c4yhvltqqwfefllg78mgk4r95");
            assertEquals(prvKey, "cPbrsHRmP4XE2ruXouVRMuEsf1PheKtJegVLLVDGfEEBUZQjyz45");
        } catch (CryptoException e) {
            e.printStackTrace();
        }

    }
}
