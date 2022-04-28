package cryptoj;

import cryptoj.classes.TXReceiver;
import cryptoj.classes.UTXObject;
import cryptoj.enums.AddressType;
import cryptoj.enums.Coin;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoJException;
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
        } catch (CryptoJException e) {
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
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_MAINNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "xpub6FMTbmnDJwazR9LAnoTn8PwZWLHzJd7jLBng6cqCAaEhp7ZMLAf1usWraE3VVqtNphkPMf6YoRDzPuwLATY362uS4FGZfdDbfDTbFH1sdwz");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_MAINNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6tvnwHiSB6q4jc7bXkJTgVTTisdsn3zMdUvyEeUCA86PVhsj1JcS9kAZXEVbNBuWCpkk7KQf6HE4b9x7mX9kp8vGAJPRhGhjgg9byG9xNvo");

            // Bitcoin regtest
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_REGTEST, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_REGTEST, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "vpub5bCa8otgRnQ7Xb7qhGFEkGwRjDz82Qfj3x9e5c2r5Xqpobz6MPaf3Zs4M6uNartStzWAuaZNZFdM3TThRTHKdN1NXbGSnXwqRgpS1kxSjtL");

            // Bitcoin testnet
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_TESTNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.BITCOIN_TESTNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "vpub5bCa8otgRnQ7Xb7qhGFEkGwRjDz82Qfj3x9e5c2r5Xqpobz6MPaf3Zs4M6uNartStzWAuaZNZFdM3TThRTHKdN1NXbGSnXwqRgpS1kxSjtL");

            // Ethereum
            xpubKey = CryptoJ.generateXPub(Network.ETHEREUM_MAINNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "xpub6E1AXXK6MkDEsbNhCefGmfZjkxyzKGiA4hHnW6L8ZmfEwP3cNdKe264ApHFo2W4fp2nwEsNxyyfQtiyg3dXtXATh8yagyJ1i5HNv5c1C2zv");
            xpubKey = CryptoJ.generateXPub(Network.ETHEREUM_MAINNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6tUrF813QV9gcPERodUnGLBQdRP2wa1CBKf1XV7zesBV2hkba3FyB8ExZ1Ujngmc12FpfaA2qQJGc5c7bNYovLm9AyVrsn72x2Gjuc1f6BG");

            // Litecoin mainnet
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN_MAINNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "Ltub2bQDUX7WAWbe8KsoQp7rwbbJ5dwtzGUyKmu9U9pLyGV8AYtALWfTwAsestHyxwSMsHjmG4JwSRGjQUsZcqt4AiSGAdbF5rZSKQQrCDh6nqj");
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN_MAINNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "zpub6toHVn6wiReBoYxhWj3BdpW2wZ4M3G17aRv4DyP4XmMENkVPZxBpDTVfPXfzyepCiDK4J83tj6hGCEzHJTxvoedykoiyy5XDcFWukSfZajk");

            // Litecoin testnet
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN_TESTNET, AddressType.P2PKH_LEGACY, mnemonic);
            assertEquals(xpubKey, "tpubDEcyGG7hNeDAkxNPCKSCn2nckLhBhqLY4kNpNWikbG5w2iJH84G88VBtG9vj1CMb8jArQbiP7CRo3QoaLUPRWZML6M9NSZVmNmqdMyk8vJf");
            xpubKey = CryptoJ.generateXPub(Network.LITECOIN_TESTNET, AddressType.P2WPKH_NATIVE_SEGWIT, mnemonic);
            assertEquals(xpubKey, "tpubDFEjGP4CSRSXVygvpAoaNNToQHNfu39nRonNzwsmBTMUf6HFvvksS8rAdYuL7B9XWBGh27GN1gAVWDBSFhxb7GpsKsQbdtF3Z6Y8YspuBtG");

            /**
             * Test function isXPubValid
             */
            Network network = Network.BITCOIN_MAINNET;
            boolean isValid = false;

            // Test cases from BIP32
            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");
            assertTrue(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "zpub6r5kw6MCdkevJCZ5XN7crPMKLKJhmh4Dk8eZPDXXwhaoSBDixyrJWu7Juwd5YdjdqZ15j1LCuGxQvZ6NVayNbLe5rvMUuHHs1JE8hxvimPn");
            assertTrue(isValid);

            // invalid xpubKeys
            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm");
            assertFalse(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn");
            assertFalse(isValid);

            isValid = CryptoJ.isXPubValid(network,
                    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4");
            assertFalse(isValid);
        } catch (CryptoJException e) {
            e.printStackTrace();
            assertTrue(false, "Invalid CryptoException catched");
        }
    }

    @Test
    @DisplayName("Test account's private key & address")
    void testAccountInfo() {
        // Generate deterministic seed
        String mnemonic = "floor earn cube small wolf elevator leaf duty deposit renew balcony chat";

        Network network = Network.BITCOIN_TESTNET;
        AddressType addrType = AddressType.P2WPKH_NATIVE_SEGWIT;

        String address;
        String xpub;
        String prvKey = "";

        try {
            network = Network.BITCOIN_MAINNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 0);
            address = CryptoJ.generateAddress(network, addrType, xpub, 0);
            assertEquals(address, "1N2cRhBBPACXzwLN5iMbTepyeknAsjSP4W");
            assertEquals(prvKey, "L3zJJbXrwr7Gk5Jbp7icqXgVYmhhyBidwnoA5axHRffjKqfZc4Gq");

            network = Network.BITCOIN_MAINNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 3);
            address = CryptoJ.generateAddress(network, addrType, xpub, 3);
            assertEquals(address, "bc1qqkhc9mjkw0rr6n5xechhnvj2lldnd8g7nc3smd");
            assertEquals(prvKey, "Kx7rDkP5ESZnhXVjBSUsRP3LChNw3VArUV2QMBuiZkNW7cqJqReC");

            network = Network.BITCOIN_TESTNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 7);
            address = CryptoJ.generateAddress(network, addrType, xpub, 7);
            assertEquals(address, "n3dJrXNo4ujsbDj7Qt4KGEHd4Sog4eg1rM");
            assertEquals(prvKey, "cVwwGkHKb49YnUd2MKRgGXkbNi94U3BfFXTKxNDhwt2xYg4KGCaa");

            network = Network.BITCOIN_TESTNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 5);
            address = CryptoJ.generateAddress(network, addrType, xpub, 5);
            assertEquals(address, "tb1q8n8cgzvje429hgygc64c3u0w77pyj7cj9fjfln");
            assertEquals(prvKey, "cV6qvG8sAzkVLjJ8oGfvLwBsdyXuKWryTcg5BYN1X4FGFF4Bfcfz");

            network = Network.BITCOIN_REGTEST;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 2);
            address = CryptoJ.generateAddress(network, addrType, xpub, 2);
            assertEquals(address, "n31cruGhMj8gFJWjUNk2HdNjqw3gCSABPa");
            assertEquals(prvKey, "cQiQ1qtkzRc83ES9zn7sAJuL7LQki6qwjCsmpKX49Y63wrQyctkR");

            network = Network.BITCOIN_REGTEST;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 1);
            address = CryptoJ.generateAddress(network, addrType, xpub, 1);
            assertEquals(address, "bcrt1qy9tr0sl96y4nt2y6axaq7ca5ajm7zma9caacuf");
            assertEquals(prvKey, "cQQ9AaCJLM79hmGiRpuik72gn3mgcGYgEQeCRnSaCgKhzhWj6gHp");

            network = Network.ETHEREUM_MAINNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 4);
            address = CryptoJ.generateAddress(network, addrType, xpub, 4);
            assertEquals(address, "0xCea857A7b2F1efA2666D0915Fa66808bd4a5E7BB");
            assertEquals(prvKey, "0x23a3d50abb6724676f34faaba2d3d0a1fb72b00a453c22d411813c1c46c01b81");

            network = Network.ETHEREUM_MAINNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 1);
            address = CryptoJ.generateAddress(network, addrType, xpub, 1);
            assertEquals(address, "bc1qlwl8qdrk26q839exs54yu2v85mls2qe9fp4ad7");
            assertEquals(prvKey, "0x4fa2c5184231d2f20a9a9e6e933758cfdcebee5f5546fc8dd72ac9461ed5ffaf");

            network = Network.LITECOIN_MAINNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 9);
            address = CryptoJ.generateAddress(network, addrType, xpub, 9);
            assertEquals(address, "LMd632NKqw44qKmqUEK6pt8nYfTsG7xQC8");
            assertEquals(prvKey, "T5H7xHs9XU5uAHQaSySZysPFMGhMgGa5pQkKDv7DLHVUK8wWXAEx");

            network = Network.LITECOIN_MAINNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 5);
            address = CryptoJ.generateAddress(network, addrType, xpub, 5);
            assertEquals(address, "ltc1qdx0stttmzlexzaresv2py8s66776plgxx4w4z4");
            assertEquals(prvKey, "T54cuK5Hd4BVTStMiw9e6oqkRsasws3pBfbJCwaQeVD74Ky5TKiy");

            network = Network.LITECOIN_TESTNET;
            addrType = AddressType.P2PKH_LEGACY;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 8);
            address = CryptoJ.generateAddress(network, addrType, xpub, 8);
            assertEquals(address, "mkmNPH2xWmn422UotCNskED9QKAvnGvcLA");
            assertEquals(prvKey, "cVdsBsrPLZsEtLxh8TQfjmdaSXDG3632zuHYBNDRDYbSvwQxwApi");

            network = Network.LITECOIN_TESTNET;
            addrType = AddressType.P2WPKH_NATIVE_SEGWIT;
            xpub = CryptoJ.generateXPub(network, addrType, mnemonic);
            prvKey = CryptoJ.generatePrivateKey(network, addrType, mnemonic, 7);
            address = CryptoJ.generateAddress(network, addrType, xpub, 7);
            assertEquals(address, "tltc1qjjrmmenxx7ca7c4yhvltqqwfefllg78mf7fkda");
            assertEquals(prvKey, "cPbrsHRmP4XE2ruXouVRMuEsf1PheKtJegVLLVDGfEEBUZQjyz45");
        } catch (CryptoJException e) {
            assertTrue(false, "Unexpected exception");
        }
    }

    @Test
    @DisplayName("Test private key validity")
    void testPrivateKey() {
        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_MAINNET, "L3zJJbXrwr7Gk5Jbp7icqXgVYmhhyBidwnoA5axHRffjKqfZc4Gq"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_MAINNET, "Kx7rDkP5ESZnhXVjBSUsRP3LChNw3VArUV2QMBuiZkNW7cqJqReC"));

        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_TESTNET, "cVwwGkHKb49YnUd2MKRgGXkbNi94U3BfFXTKxNDhwt2xYg4KGCaa"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_TESTNET, "cV6qvG8sAzkVLjJ8oGfvLwBsdyXuKWryTcg5BYN1X4FGFF4Bfcfz"));

        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_REGTEST, "cQiQ1qtkzRc83ES9zn7sAJuL7LQki6qwjCsmpKX49Y63wrQyctkR"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.BITCOIN_REGTEST, "cQQ9AaCJLM79hmGiRpuik72gn3mgcGYgEQeCRnSaCgKhzhWj6gHp"));

        assertTrue(CryptoJ.isPrivKeyValid(Network.ETHEREUM_MAINNET, "0x23a3d50abb6724676f34faaba2d3d0a1fb72b00a453c22d411813c1c46c01b81"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.ETHEREUM_MAINNET, "0x4fa2c5184231d2f20a9a9e6e933758cfdcebee5f5546fc8dd72ac9461ed5ffaf"));

        assertTrue(CryptoJ.isPrivKeyValid(Network.LITECOIN_MAINNET, "T5H7xHs9XU5uAHQaSySZysPFMGhMgGa5pQkKDv7DLHVUK8wWXAEx"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.LITECOIN_MAINNET, "T54cuK5Hd4BVTStMiw9e6oqkRsasws3pBfbJCwaQeVD74Ky5TKiy"));

        assertTrue(CryptoJ.isPrivKeyValid(Network.LITECOIN_TESTNET, "cVdsBsrPLZsEtLxh8TQfjmdaSXDG3632zuHYBNDRDYbSvwQxwApi"));
        assertTrue(CryptoJ.isPrivKeyValid(Network.LITECOIN_TESTNET, "cPbrsHRmP4XE2ruXouVRMuEsf1PheKtJegVLLVDGfEEBUZQjyz45"));

        // invalid key - containing invalid character
        assertFalse(CryptoJ.isPrivKeyValid(Network.BITCOIN_MAINNET, "L3zJJbXrwr7Gk5Jbp7IcqXgVYmhhyBidwnoA5axHRffjKqfZc4Gq"));
        // invalid key - checksum validation failed
        assertFalse(CryptoJ.isPrivKeyValid(Network.BITCOIN_MAINNET, "Kx7rDkP5ESZnhXVjBSUsRP3ChNw3VArUV2QMBuiZkNW7cqJqReC"));
        // invalid key - invalid network
        assertFalse(CryptoJ.isPrivKeyValid(Network.BITCOIN_MAINNET, "cVwwGkHKb49YnUd2MKRgGXkbNi94U3BfFXTKxNDhwt2xYg4KGCaa"));

        // TODO: ... add some test cases
    }

    @Test
    @DisplayName("Test address validity")
    void testAddress() {
        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_MAINNET, "1N2cRhBBPACXzwLN5iMbTepyeknAsjSP4W"));
        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_MAINNET, "bc1qqkhc9mjkw0rr6n5xechhnvj2lldnd8g7nc3smd"));

        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_TESTNET, "n3dJrXNo4ujsbDj7Qt4KGEHd4Sog4eg1rM"));
        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_TESTNET, "tb1q8n8cgzvje429hgygc64c3u0w77pyj7cj9fjfln"));

        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_REGTEST, "n31cruGhMj8gFJWjUNk2HdNjqw3gCSABPa"));
        assertTrue(CryptoJ.isAddressValid(Network.BITCOIN_REGTEST, "bcrt1qy9tr0sl96y4nt2y6axaq7ca5ajm7zma9caacuf"));

        assertTrue(CryptoJ.isAddressValid(Network.ETHEREUM_MAINNET, "0xCea857A7b2F1efA2666D0915Fa66808bd4a5E7BB"));
        assertTrue(CryptoJ.isAddressValid(Network.ETHEREUM_MAINNET, "bc1qlwl8qdrk26q839exs54yu2v85mls2qe9fp4ad7"));

        assertTrue(CryptoJ.isAddressValid(Network.LITECOIN_MAINNET, "LMd632NKqw44qKmqUEK6pt8nYfTsG7xQC8"));
        assertTrue(CryptoJ.isAddressValid(Network.LITECOIN_MAINNET, "ltc1qdx0stttmzlexzaresv2py8s66776plgxx4w4z4"));

        assertTrue(CryptoJ.isAddressValid(Network.LITECOIN_TESTNET, "mkmNPH2xWmn422UotCNskED9QKAvnGvcLA"));
        assertTrue(CryptoJ.isAddressValid(Network.LITECOIN_TESTNET, "litecointestnet1qjjrmmenxx7ca7c4yhvltqqwfefllg78mgk4r95"));

        // invalid key - containing invalid character - I
        assertFalse(CryptoJ.isAddressValid(Network.BITCOIN_MAINNET, "IN2cRhBBPACXzwLN5iMbTepyeknAsjSP4W"));
        // invalid key - checksum validation failed - some characters removed
        assertFalse(CryptoJ.isAddressValid(Network.BITCOIN_MAINNET, "bc1qqkhc9mjkw0rr6n5xechhnvldnd8g7nc3smd"));
        // invalid key - invalid network - address should be TESTNET
        assertFalse(CryptoJ.isAddressValid(Network.BITCOIN_MAINNET, "n3dJrXNo4ujsbDj7Qt4KGEHd4Sog4eg1rM"));

        // TODO: ... add some test cases
    }

    @Test
    @DisplayName("Test transaction")
    void testBTCTransaction() {
        final double transactionFee = 0.00000225;
        UTXObject[] utxos;
        TXReceiver[] receivers;
        String signedTx = null;


        // Test case - 1: Legacy to Legacy
        utxos = new UTXObject[] {
            new UTXObject(
                    "f9cd04069952d1926ac49f725d9e3bd13ef00afe5602411dee73d54655928cb0",
                    1L,
                    "cSSs15Tp7Sq4vrxfDhgNYFupWnF6VXm7cf828HkyS563sLYhe3QE"
            )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("n1ZfpnjSugDUFe2wc3sw1LrwRYQ9N1hf7y", 0.0001),
                new TXReceiver("mxJsqhDcZh2UCKrcVz7ZvMB1y4yJ5iMMxA", 0.00073 - 0.0001 - transactionFee) // change
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.BTC, Network.BITCOIN_TESTNET, utxos, receivers);
            System.out.println("Send from " + receivers[1].getAddress() + " to " + receivers[0].getAddress());
            System.out.println("    Amount " + receivers[0].getAmount());
            System.out.println("    Change " + receivers[1].getAmount());
            System.out.println("Signed transaction data:");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Test case - 2: Legacy to Segwit
        utxos = new UTXObject[] {
                new UTXObject(
                        "a6af4d0c9fbc22fc2ca2b77e93088ce0f1a36e8a56d9e4aaa6fad68e282d8e68",
                        1L,
                        "cSSs15Tp7Sq4vrxfDhgNYFupWnF6VXm7cf828HkyS563sLYhe3QE"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("tb1q8n8cgzvje429hgygc64c3u0w77pyj7cj9fjfln", 0.0001),
                new TXReceiver("mxJsqhDcZh2UCKrcVz7ZvMB1y4yJ5iMMxA", 0.001 - 0.0001 - transactionFee) // change
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.BTC, Network.BITCOIN_TESTNET, utxos, receivers);
            System.out.println("Send from " + receivers[1].getAddress() + " to " + receivers[0].getAddress());
            System.out.println("    Amount " + receivers[0].getAmount());
            System.out.println("    Change " + receivers[1].getAmount());
            System.out.println("Signed transaction data:");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Test case - 3: Segwit to Legacy
        utxos = new UTXObject[] {
                new UTXObject(
                        "066af46627ae8271b0f5f9064f72fc339a0dbcdd2e3f94826bce256b3c1c0ef4",
                        0L,
                        "cP7ze2fsK5v7JxTQz2iY4bhqvfwLEANjTx8EsowERivCiPqrK14a"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("n1ZfpnjSugDUFe2wc3sw1LrwRYQ9N1hf7y", 0.000004),
                new TXReceiver("tb1q5ec53yn0y2l8ghe9w7n5lvp76zkshf899zft2p", 0.00001 - 0.000004 - transactionFee) // change
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.BTC, Network.BITCOIN_TESTNET, utxos, receivers);
            System.out.println("Send from " + receivers[1].getAddress() + " to " + receivers[0].getAddress());
            System.out.println("    Amount " + receivers[0].getAmount());
            System.out.println("    Change " + receivers[1].getAmount());
            System.out.println("Signed transaction data:");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Test case - 4: Segwit to Segwit
        utxos = new UTXObject[] {
                new UTXObject(
                        "066af46627ae8271b0f5f9064f72fc339a0dbcdd2e3f94826bce256b3c1c0ef4",
                        1L,
                        "cV6qvG8sAzkVLjJ8oGfvLwBsdyXuKWryTcg5BYN1X4FGFF4Bfcfz"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("tb1q5ec53yn0y2l8ghe9w7n5lvp76zkshf899zft2p", 0.00004),
                new TXReceiver("tb1q8n8cgzvje429hgygc64c3u0w77pyj7cj9fjfln", 0.00008859 - 0.00004 - transactionFee) // change
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.BTC, Network.BITCOIN_TESTNET, utxos, receivers);
            System.out.println("Send from " + receivers[1].getAddress() + " to " + receivers[0].getAddress());
            System.out.println("    Amount " + receivers[0].getAmount());
            System.out.println("    Change " + receivers[1].getAmount());
            System.out.println("Signed transaction data:");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Test case 5: merge UTXOs

        utxos = new UTXObject[] {
                new UTXObject(
                        "bc3780eca9b191ec1f3b8cda10d85ac2e4c308d657a025607ddafb9f2bb26adc",
                        0L,
                        "cP7ze2fsK5v7JxTQz2iY4bhqvfwLEANjTx8EsowERivCiPqrK14a"
                ),
                new UTXObject(
                        "766ad20a0687c9d163aea5d8d5efe3d618ba4ffeb8c837c44221d3c59ef7b4c2",
                        1L,
                        "cP7ze2fsK5v7JxTQz2iY4bhqvfwLEANjTx8EsowERivCiPqrK14a"
                ),
                new UTXObject(
                        "dd3eb16bfc6a08534d6ca4afc19f789d551eee28797edb48f71827b5cb03d4b0",
                        0L,
                        "cP7ze2fsK5v7JxTQz2iY4bhqvfwLEANjTx8EsowERivCiPqrK14a"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("tb1q5ec53yn0y2l8ghe9w7n5lvp76zkshf899zft2p", 0.00004000) // change
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.BTC, Network.BITCOIN_TESTNET, utxos, receivers);
            System.out.println("Merging balance of address tb1q5ec53yn0y2l8ghe9w7n5lvp76zkshf899zft2p");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }
    }

    @Test
    @DisplayName("Test Litecoin Transaction")
    void testLTCTransaction() {
        final double transactionFee = 0.00000225;
        UTXObject[] utxos;
        TXReceiver[] receivers;
        String signedTx = null;

        // Testing legacy -> legacy
        utxos = new UTXObject[] {
                new UTXObject(
                        "294aeaeab186bde9981aee39a0741e944a30245675f732005ba19cc7d78d5761",
                        0L,
                        "cNoirL31g43BHyKr8suPgfbStzCWPgQXs3eezj3q1gm5AMEDoq4f"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("n4ZF3QSdqyENX6nH7h3EUejMixx2qKXc7t", 0.12499526),
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.LTC, Network.LITECOIN_TESTNET, utxos, receivers);
            System.out.println("n1bcns8QWs8zeGo9KhSANqdM8ychQ3w7UN -> n4ZF3QSdqyENX6nH7h3EUejMixx2qKXc7t");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Testing legacy -> segwit
        utxos = new UTXObject[] {
                new UTXObject(
                        "35e795079e25bbfcc5ec9aeb8243308bb6ff645f3e414c786905149ccbbe93f1",
                        0L,
                        "cVQ4DTWzG6d3W9rBijEzVMTJGDkm2Pb7MtG82B1arxQrYDx543u2"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("litecointestnet1qhuukwzakzyqr0ekypxd9z8yz28t7rf5t8vsxpm", 0.12499326),
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.LTC, Network.LITECOIN_TESTNET, utxos, receivers);
            System.out.println("n4ZF3QSdqyENX6nH7h3EUejMixx2qKXc7t -> litecointestnet1qhuukwzakzyqr0ekypxd9z8yz28t7rf5t8vsxpm");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Testing segwit -> segwit
        utxos = new UTXObject[] {
                new UTXObject(
                        "a9cae8aadde742aa910f6db7af869bdbc9a4aff184c6edbcf8b96c27c08c8300",
                        0L,
                        "cMywNUMjcs8diyGyZbJuj1sfdnNiKoTJzxQTYSLSojjyA3DPkHbT"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("litecointestnet1qycv90vfra7z65zk0rzv9dzymy0fzulsx3wynfv", 0.12499126),
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.LTC, Network.LITECOIN_TESTNET, utxos, receivers);
            System.out.println("litecointestnet1qhuukwzakzyqr0ekypxd9z8yz28t7rf5t8vsxpm -> litecointestnet1qycv90vfra7z65zk0rzv9dzymy0fzulsx3wynfv");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }

        // Testing segwit -> legacy
        utxos = new UTXObject[] {
                new UTXObject(
                        "b0e63a2649259ef54cceeaf9682b6aa38c9c172fe6dc8ba77cce5298b9ba3c48",
                        0L,
                        "cTvwDi387CeKsgMKG8L2bquMTJaHGTnvWXvsCHQoNNy1H3Szq2RT"
                )
        };

        receivers = new TXReceiver[] {
                new TXReceiver("n4ZF3QSdqyENX6nH7h3EUejMixx2qKXc7t", 0.12498926),
        };

        try {
            signedTx = CryptoJ.signBitcoinBasedTransaction(Coin.LTC, Network.LITECOIN_TESTNET, utxos, receivers);
            System.out.println("litecointestnet1qycv90vfra7z65zk0rzv9dzymy0fzulsx3wynfv -> n4ZF3QSdqyENX6nH7h3EUejMixx2qKXc7t");
            System.out.println(signedTx);
            System.out.println("");
        } catch (CryptoJException e) {
            e.printStackTrace();
        }
    }
}
