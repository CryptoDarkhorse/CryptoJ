package cryptoj;

import com.google.common.base.Splitter;
import cryptoj.classes.TXReceiver;
import cryptoj.classes.UTXObject;
import cryptoj.enums.AddressType;
import cryptoj.enums.Coin;
import cryptoj.enums.CoinType;
import cryptoj.enums.Network;
import cryptoj.demos.Demo_2_SignAndVerifyMessage;
import cryptoj.exceptions.CryptoJException;
import cryptoj.network.IWrappedNetParams;
import cryptoj.network.WrappedMainNetParams;
import cryptoj.network.WrappedTestNetParams;
import lombok.NonNull;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.*;

/**
 * Universal and easy-to-integrate java library for java/blockchain developers. By calling just
 * one simple method you easily can:<br>
 * <br>
 * <li>
 * Generate mnemonics (seeds)
 * </li>
 * <li>
 * Generate xpubs (extened public keys / wallets)
 * </li>
 * <li>
 * Generate addresses and private keys
 * </li>
 * <li>
 * Sign and verify a text message
 * </li>
 * <li>
 * Prepare a signed transaction for broadcasting
 * </li>
 * <br>
 * <i>Note: Supports Bitcoin, Litecoin, Ethereum (mainnets + testnets)</i>
 *
 * @author Marek Lorenc (me.marek.lorenc@gmail.com), Jordan Cameron (c.knight8817@gmail.com)
 * @version 1.0
 */
public class CryptoJ {


    // SECTION - MNEMONIC //

    /**
     * Generate mnemonic
     *
     * @param length min value 12, max value 24, multiply of 3
     * @return mnemonic phrase made of words
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generateMnemonic(
            @NonNull Integer length
    ) throws CryptoJException {
        return generateMnemonic(length, null);
    }

    /**
     * Generate mnemonic.
     *
     * @param length     min value 12, max value 24, multiply of 3
     * @param passphrase passphrase used to encrypt key - empty string means non-encrypted key
     * @return mnemonic phrase made of words
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generateMnemonic(
            @NonNull Integer length,
            String passphrase
    ) throws CryptoJException {
        // check word length
        if (length < 12 || length > 24 || length % 3 > 0)
            throw new CryptoJException("Invalid word length: it must be between 12 and 24, and multiple of 3");

        // fix passphrase
        if (passphrase == null) {
            passphrase = "";
        }

        int checkSumLen = length / 3;
        int entropyLen = length * 11 - checkSumLen;

        // Generate deterministic seed
        DeterministicSeed seed = new DeterministicSeed(new SecureRandom(), entropyLen, passphrase);

        // Get mnemonic from seed
        List<String> words = seed.getMnemonicCode();

        // Concat word list
        String mnemonic = String.join(" ", words);

        // internal validation
        if (isMnemonicValid(mnemonic) == false) {
            throw new CryptoJException("Internal validation (mnemonic) has failed.");
        }

        return mnemonic;
    }

    /**
     * Validate mnemonic.
     *
     * @param mnemonic to be validated
     * @return true if it's valid, otherwise false
     */
    public static boolean isMnemonicValid(
            @NonNull String mnemonic
    ) {
        // Split mnemonic string by space
        List<String> words = Splitter.on(' ').splitToList(mnemonic);

        // check by MnemonicCode class of BitcoinJ
        try {
            MnemonicCode.INSTANCE.check(words);
            return true;
        } catch (MnemonicException e) {
            return false;
        }
    }


    // SECTION - XPUB //

    /**
     * Generate xPub (extended public key).<br>
     * <br>
     * <strong>Note:</strong> Extended public key of LiteCoin have 2 kinds of prefixes - xpub & Ltpub
     * However, this is only difference of notation, and results are same.
     * And most LiteCoin wallets support all of these 2 types and toggle using a checkbox
     * which has label "Use Ltpv / Ltub instead of xprv / xpub" or so.
     *
     * @param network  network
     * @param addrType address type
     * @param mnemonic phrase made of words
     * @return extened public key
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generateXPub(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String mnemonic
    ) throws CryptoJException {
        return generateXPub(
                network,
                addrType,
                mnemonic,
                null
        );
    }

    /**
     * Generate xPub (extended public key).<br>
     * <br>
     * <strong>Note:</strong> Extended public key of LiteCoin have 2 kinds of prefixes - xpub & Ltpub
     * However, this is only difference of notation, and results are same.
     * And most LiteCoin wallets support all of these 2 types and toggle using a checkbox
     * which has label "Use Ltpv / Ltub instead of xprv / xpub" or so.
     *
     * @param network    network
     * @param addrType   address type
     * @param mnemonic   phrase made of words
     * @param passphrase which was used when mnemonic was generated
     * @return extened public key
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generateXPub(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String mnemonic,
            String passphrase
    ) throws CryptoJException {

        if (addrType.getPurpose() < 0) {
            throw new CryptoJException("P2SH does not support HD wallet");
        }

        if (isMnemonicValid(mnemonic) == false) {
            throw new CryptoJException("Mnemonic is not valid.");
        }

        // fix passphrase
        if (passphrase == null) {
            passphrase = "";
        }

        DeterministicSeed seed;
        try {
            seed = new DeterministicSeed(mnemonic, null, passphrase, 0);
        } catch (UnreadableWalletException e) {
            throw new CryptoJException("Invalid mnemonic");
        }

        /**
         * Build HD path
         * Ref: BIP 44 - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
         */
        HDPath path = HDPath.m();

        // extend purpose - current path is m/purpose'
        path = path.extend(new ChildNumber(addrType.getPurpose(), true)); // /purpose'

        // extend coin type - current path is m/purpose'/coin_type'
        if (network.isMainNet()) {
            path = path.extend(new ChildNumber(network.getCoinId(), true));
        } else {
            // purpose value of testnet is 1 for all coin types
            path = path.extend(new ChildNumber(1, true));
        }

        // extend account & change - m/purpose'/coin_type'/account'/change
        path = path.extend(new ChildNumber(0, true));
        path = path.extend(new ChildNumber(0, false));

        DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed).build();

        DeterministicKey key = chain.getKeyByPath(path, true);

        NetworkParameters params = getNetworkParams(network);

        String xPub = "";
        if (addrType.equals(AddressType.P2PKH_LEGACY)) {
            xPub = key.serializePubB58(params, Script.ScriptType.P2PKH);
        } else {
            xPub = key.serializePubB58(params, Script.ScriptType.P2WPKH);
        }

        // internal validation
        if (isXPubValid(network, xPub) == false) {
            throw new CryptoJException("Internal validation (xPub) has failed.");
        }

        return xPub;
    }

    /**
     * Validate xPub (extended public key).
     *
     * @param network network
     * @param xPub    xPub to be validated
     * @return true if it's valid, otherwise false
     */
    public static boolean isXPubValid(
            @NonNull Network network,
            @NonNull String xPub
    ) {
        NetworkParameters params = getNetworkParams(network);

        try {
            DeterministicKey key = DeterministicKey.deserializeB58(xPub, params);
            return key.isPubKeyOnly();// extended private key
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }


    // SECTION - ADDRESS //

    /**
     * Generate blockchain address for receiving coins.
     *
     * @param network         network
     * @param addrType        address type
     * @param xPub            xpub to generate the address from
     * @param derivationIndex derivation index
     * @return address for receiving coins
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generateAddress(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String xPub,
            @NonNull int derivationIndex
    ) throws CryptoJException {

        if (isXPubValid(network, xPub) == false) {
            throw new CryptoJException("Invalid xPub.");
        }

        if (derivationIndex < 0) {
            throw new CryptoJException("Invalid derivation index (must be greater or equal to zero).");
        }

        NetworkParameters params = getNetworkParams(network);

        DeterministicKey xpubKey = DeterministicKey.deserializeB58(xPub, params);

        DeterministicKey key = HDKeyDerivation.deriveChildKey(xpubKey, new ChildNumber(derivationIndex, false));

        Script.ScriptType scryptType = Script.ScriptType.P2PKH;

        switch (addrType) {
            case P2PKH_LEGACY:
                scryptType = Script.ScriptType.P2PKH;
                break;
            case P2WPKH_NATIVE_SEGWIT:
            case P2TR_TAPROOT:
                scryptType = Script.ScriptType.P2WPKH;
                break;
            case P2SH_PAY_TO_SCRIPT_HASH:
                throw new CryptoJException("P2SH does not support HD wallet");
            default:
                throw new CryptoJException("Unsupported address type");
        }

        Address address = Address.fromKey(params, key, scryptType);

        String encodedAddress = "";
        switch (network.getCoinType()) {
            case ETH:
                if (addrType == AddressType.P2PKH_LEGACY) {
                    byte[] encoded = key.getPubKeyPoint().getEncoded(false);
                    BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
                    return Keys.toChecksumAddress(Keys.getAddress(publicKey));
                }
            case BTC:
            case LTC:
                encodedAddress = address.toString();
                break;
            default:
                throw new CryptoJException("Unsupported network");
        }

        // internal validation
        if (isAddressValid(network, encodedAddress) == false) {
            throw new CryptoJException("Internal validation (address) has failed.");
        }

        return encodedAddress;
    }

    /**
     * Validate blockchain address for receiving coins.
     *
     * @param network network
     * @param address to be validated
     * @return true if it's valid, otherwise false
     */
    public static boolean isAddressValid(
            @NonNull Network network,
            @NonNull String address
    ) {
        NetworkParameters params = getNetworkParams(network);

        if (network.getCoinType() == CoinType.ETH && address.startsWith("0x")) {
            // ethereum legacy address
            return Utils.HEX.canDecode(address.toLowerCase().substring(2)) && // only hexadecimal characters
                    address.length() == 42; // 20bytes + "0x" = 42 characters
        }

        try {
            Address.fromString(params, address);
            return true;
        } catch (AddressFormatException ex) {
            return false;
        }
    }

    /**
     * Validate blockchain address for receiving coins.
     *
     * @param address to be validated
     * @return collection of networks for which the address is valid
     * If the address is not valid at all, the resulting collection will be empty
     */
    public static Collection<Network> isAddressValid(
            @NonNull String address
    ) {
        Collection<Network> result = new HashSet();
        for (Network network : Network.values()) {
            if (isAddressValid(network, address)) {
                result.add(network);
            }
        }
        return Collections.unmodifiableCollection(result);
    }


    // SECTION - PRIVATE KEY //

    /**
     * Generate private key for an address.
     *
     * @param network         network
     * @param addrType        address type
     * @param mnemonic        mnemonic
     * @param derivationIndex of the address which to generate the private key for
     * @return private key of the address on specific derivation index
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generatePrivateKey(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String mnemonic,
            @NonNull int derivationIndex
    ) throws CryptoJException {
        return generatePrivateKey(
                network,
                addrType,
                mnemonic,
                null,
                derivationIndex
        );
    }

    /**
     * Generate private key for an address.
     *
     * @param network         network
     * @param addrType        address type
     * @param mnemonic        mnemonic
     * @param passphrase      which was used when mnemonic was generated
     * @param derivationIndex of the address which to generate the private key for
     * @return private key of the address on specific derivation index
     * @throws CryptoJException if method params are invalid or internal validation of generated result fails
     */
    public static String generatePrivateKey(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String mnemonic,
            String passphrase,
            @NonNull int derivationIndex
    ) throws CryptoJException {

        if (addrType.getPurpose() < 0) {
            throw new CryptoJException("P2SH does not support HD wallet");
        }

        if (isMnemonicValid(mnemonic) == false) {
            throw new CryptoJException("Invalid mnemonic");
        }

        // fix passphrase
        if (passphrase == null) {
            passphrase = "";
        }

        if (derivationIndex < 0) {
            throw new CryptoJException("Invalid derivation index (must be greater or equal to zero).");
        }

        DeterministicSeed seed;
        try {
            seed = new DeterministicSeed(mnemonic, null, passphrase, 0);
        } catch (UnreadableWalletException e) {
            throw new CryptoJException("Invalid mnemonic");
        }

        /**
         * Build HD path
         * Ref: BIP 44 - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
         */
        HDPath path = HDPath.m();

        // extend purpose - m/purpose'
        path = path.extend(new ChildNumber(addrType.getPurpose(), true));

        // extend coin type - m/purpose'/coin_type'
        if (network.isMainNet()) {
            path = path.extend(new ChildNumber(network.getCoinId(), true));
        } else {
            // purpose value of testnet is 1 for all coin types
            path = path.extend(new ChildNumber(1, true));
        }

        // extend account & change - m/purpose'/coin_type'/account'/change
        path = path.extend(new ChildNumber(0, true));
        path = path.extend(new ChildNumber(0, false));

        // extend derivation index
        path = path.extend(new ChildNumber(derivationIndex, false));

        DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed).build();

        DeterministicKey key = chain.getKeyByPath(path, true);
        NetworkParameters params = getNetworkParams(network);

        String privKey = "";
        switch (network.getCoinType()) {
            case BTC:
            case LTC:
                privKey = key.getPrivateKeyAsWiF(params);
                break;
            case ETH:
                privKey = "0x" + key.getPrivateKeyAsHex();
                break;
            default:
                throw new CryptoJException("Unsupported network");
        }

        // internal validation
        if (isPrivKeyValid(network, privKey) == false) {
            throw new CryptoJException("Internal validation (private key) has failed.");
        }

        return privKey;
    }

    /**
     * Validate private key.
     *
     * @param network    network
     * @param privateKey to be validated
     * @return true if it's valid, otherwise false
     */
    public static boolean isPrivKeyValid(
            @NonNull Network network,
            @NonNull String privateKey
    ) {
        NetworkParameters params = getNetworkParams(network);

        if (network.getCoinType() == CoinType.ETH) {
            privateKey = privateKey.toLowerCase();
            if (!privateKey.startsWith("0x")) return false;

            try {
                byte[] privKeyBytes = Utils.HEX.decode(privateKey.substring(2));
                ECKey.fromPrivate(privKeyBytes);
                return true;
            } catch (IllegalArgumentException ex) {
                return false;
            }
        }

        try {
            DumpedPrivateKey.fromBase58(params, privateKey);
            return true;
        } catch (AddressFormatException ex) {
            return false;
        }
    }


    // SECTION - SIGN & VERIFY A TEXT MESSAGE //

    /**
     * Signs any raw text message using specific private key.
     * See {@link Demo_2_SignAndVerifyMessage}
     *
     * @param network network
     * @param rawMessage to be signed
     * @param privateKey to use to sign the raw message
     * @return Signature of message
     */
    public static String signMessage(
            @NonNull Network network,
            @NonNull String rawMessage,
            @NonNull String privateKey
    ) throws CryptoJException {
        ECKey key = null;
        if (network.getCoinType() == CoinType.ETH) {
            privateKey = privateKey.toLowerCase();

            if (!privateKey.startsWith("0x"))
                throw new CryptoJException("Invalid private key");

            try {
                byte[] privKeyBytes = Utils.HEX.decode(privateKey.substring(2));
                key = ECKey.fromPrivate(privKeyBytes);
            } catch (IllegalArgumentException ex) {
                throw new CryptoJException("Invalid private key");
            }
        } else {
            try {
                key = DumpedPrivateKey.fromBase58(getNetworkParams(network), privateKey).getKey();
            } catch (AddressFormatException ex) {
                throw new CryptoJException("Invalid private key");
            }
        }
        return key.signMessage(rawMessage);
    }

    /**
     * Verifies signature of a raw message, if the raw message was signed using private key of specific address.
     * See {@link Demo_2_SignAndVerifyMessage}
     *
     * @param network network
     * @param rawMessage a raw text message which was signed by private key
     * @param signature  signature provided by address owner
     * @param address    which private key signed the raw message and created the signature
     * @return true if signature is valid, otherwise false
     */
    public static boolean verifyMessage(
            @NonNull Network network,
            @NonNull String rawMessage,
            @NonNull String signature,
            @NonNull String address
    ) {
        try {
            NetworkParameters params = getNetworkParams(network);
            ECKey key = ECKey.signedMessageToKey(rawMessage, signature);

            if (network.getCoinType() == CoinType.ETH && address.startsWith("0x")) {
                byte[] encoded = key.getPubKeyPoint().getEncoded(false);
                BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
                address = address.toLowerCase();
                String addressVerified = Keys.toChecksumAddress(Keys.getAddress(publicKey)).toLowerCase();
                return address.equals(addressVerified);
            }
            Address addr = Address.fromString(params, address);
            Address addrVerified = Address.fromKey(params, key, addr.getOutputScriptType());
            return addr.equals(addrVerified);
        } catch (SignatureException e) {
            return false;
        }
    }


    // SECTION - SIGN TRANSACTION //

    /**
     * Prepares signed transaction ready to be broadcast.
     *
     * @param coin        to be sent
     * @param network     on which the transaction will be broadcast
     * @param utxobjects  inputs
     * @param txReceivers outputs
     * @return signed transaction ready to be broadcast
     * @throws CryptoJException if signing failed
     */
    public static String signBitcoinBasedTransaction(
            @NonNull Coin coin,
            @NonNull Network network,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoJException {
        CoinType coinType = coin.getCoinType();
        if (coinType != CoinType.BTC && coinType != CoinType.LTC) {
            throw new CryptoJException("Invalid coin type.");
        }
        if (coin.getNetworks().contains(network) == false) {
            throw new CryptoJException("Invalid coin and network combination.");
        }
        for (UTXObject utxo : utxobjects) {
            utxo.setTxRawData(utxo.getTxRawData().replace(" ", ""));
            if (utxo.getTxRawData().isEmpty()) {
                throw new CryptoJException("Invalid UTXO txRawData.");
            }
            if (utxo.getIndex() < 0) {
                throw new CryptoJException("Invalid UTXO index.");
            }
            utxo.setPrivKey(utxo.getPrivKey().replace(" ", ""));
            if (isPrivKeyValid(network, utxo.getPrivKey()) == false) {
                throw new CryptoJException("Sender's private key " + utxo.getPrivKey() + " is invalid.");
            }
        }
        for (TXReceiver txReceiver : txReceivers) {
            txReceiver.setAddress(txReceiver.getAddress().replace(" ", ""));
            if (isAddressValid(network, txReceiver.getAddress()) == false) {
                throw new CryptoJException("Receiver's address " + txReceiver.getAddress() + " is invalid.");
            }
            BigDecimal amount = txReceiver.getAmount().stripTrailingZeros();
            int scale = coin.getScale();
            RoundingMode rm = RoundingMode.DOWN;
            if (amount.setScale(scale, rm).compareTo(amount) == 0) { // check if amount has valid scale
                throw new CryptoJException("Receiver's amount scale is invalid.");
            }
            amount = amount.setScale(scale, rm);
            if (amount.compareTo(coin.getMinValue()) < 0) {
                throw new CryptoJException("Receiver's amount " + amount + " is less than min " + coin.getMinValue() + " " + coin.getCode() + ".");
            }
            txReceiver.setAmount(amount);
        }
        return doSignBitcoinBasedTransaction(
                network,
                utxobjects,
                txReceivers
        );
    }

    /**
     * Prepares signed transaction ready to be broadcast.
     *
     * @param network           on which the transaction is to be broadcast
     * @param fromPrivateKey    of an address which the funds is be sent from
     * @param toAddress         where the funds is to be sent to
     * @param amount            absolute amount in full units, for example 1.123456789012345678 ETH
     * @param coin              which is to be sent
     * @param nonce             nonce
     * @param gasPriceInETHWei  in wei. So for example value '150' means '150wei', which is 0.000000000000000150 ETH
     * @param gasLimitInUnits   for example 20000 for classic ethereum ETH transaction
     * @return signed transaction ready to be broadcast.
     * @throws CryptoJException if signing failed
     */
    public static String signEthereumBasedTransaction(
            @NonNull Network network,
            @NonNull String fromPrivateKey,
            @NonNull String toAddress,
            @NonNull BigDecimal amount,
            @NonNull Coin coin,
            @NonNull BigInteger nonce,
            @NonNull BigInteger gasPriceInETHWei,
            @NonNull BigInteger gasLimitInUnits
    ) throws CryptoJException {
        CoinType coinType = coin.getCoinType();
        if (coinType != CoinType.ETH) {
            throw new CryptoJException("Invalid coin type.");
        }
        if (coin.getNetworks().contains(network) == false) {
            throw new CryptoJException("Invalid coin and network combination.");
        }
        fromPrivateKey = fromPrivateKey.replace(" ", "");
        if (isPrivKeyValid(network, fromPrivateKey) == false) {
            throw new CryptoJException("Private key is invalid.");
        }
        toAddress = toAddress.replace(" ", "");
        if (isAddressValid(network, toAddress) == false) {
            throw new CryptoJException("To address is invalid.");
        }
        amount = amount.stripTrailingZeros();
        int scale = coin.getScale();
        RoundingMode rm = RoundingMode.DOWN;
        if (amount.setScale(scale, rm).compareTo(amount) != 0) { // check if amount has valid scale
            throw new CryptoJException("Invalid amount scale.");
        }
        amount = amount.setScale(scale, rm);
        if (amount.compareTo(coin.getMinValue()) < 0) {
            throw new CryptoJException("Amount is less than min " + coin.getMinValue() + " " + coin.getCode() + ".");
        }
        if (nonce.compareTo(BigInteger.ZERO) < 0) {
            throw new CryptoJException("Invalid nonce. Must be greater or equal to zero.");
        }
        if (gasPriceInETHWei.compareTo(BigInteger.ZERO) <= 0) {
            throw new CryptoJException("Invalid gas price in wei. Must be greater than zero.");
        }
        if (gasLimitInUnits.compareTo(BigInteger.ZERO) <= 0) {
            throw new CryptoJException("Invalid gas limit in units. Must be greater than zero.");
        }
        return doSignEthereumBasedTransaction(
                fromPrivateKey,
                toAddress,
                coin,
                amount,
                nonce,
                gasPriceInETHWei,
                gasLimitInUnits,
                !network.isMainNet()
        );
    }


    // SECTION - OTHERS //

    /**
     * Get network parameters.
     *
     * @param network from which to get network parameters
     * @return network parameters
     */
    public static NetworkParameters getNetworkParams(
            @NonNull Network network
    ) {
        IWrappedNetParams wrappedParams = null;
        NetworkParameters params = null;

        if (network.isMainNet()) {
            params = WrappedMainNetParams.get();
            wrappedParams = WrappedMainNetParams.get();
        } else {
            params = WrappedTestNetParams.get();
            wrappedParams = WrappedTestNetParams.get();
        }

        wrappedParams.setBIP32Headers(
                network.getBech32(),
                network.getPubKeyHash(),
                network.getScriptHash(),
                network.getWif(),
                network.getP2pkhPub(),
                network.getP2pkhPriv(),
                network.getP2wpkhPub(),
                network.getP2wpkhPriv()
        );

        return params;
    }


    // SECTION - PRIVATE LOCAL METHODS //

    private static String doSignBitcoinBasedTransaction(
            @NonNull Network network,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoJException {
        NetworkParameters params = getNetworkParams(network);

        Context.getOrCreate(params);

        // Init transaction
        Transaction trans = new Transaction(params);
        trans.setVersion(2);

        // Add inputs
        for (int i = 0; i < utxobjects.length; i++) {
            UTXObject utxo = utxobjects[i];
            Transaction prevTrans = new Transaction(params, Utils.HEX.decode(utxo.getTxRawData()));
            trans.addInput(prevTrans.getOutput(utxo.getIndex()));
        }

        // Add outputs
        for (int i = 0; i < txReceivers.length; i++) {
            TXReceiver receiver = txReceivers[i];
            Address addr = Address.fromString(params, receiver.getAddress());
            Script scriptPubKey = ScriptBuilder.createOutputScript(addr);
            trans.addOutput(org.bitcoinj.core.Coin.valueOf(org.bitcoinj.core.Coin.btcToSatoshi(receiver.getAmount())), scriptPubKey);
        }

        // Sign inputs
        for (int i = 0; i < utxobjects.length; i++) {
            UTXObject utxo = utxobjects[i];

            ECKey key = DumpedPrivateKey.fromBase58(params, utxo.getPrivKey()).getKey();

            TransactionInput input = trans.getInput(i);
            TransactionOutput output = input.getConnectedOutput();

            Transaction.SigHash sigHash = Transaction.SigHash.ALL;
            boolean anyoneCanPay = false;
            Script scriptPubKey = output.getScriptPubKey();

            TransactionSignature signature;
            if (ScriptPattern.isP2PK(scriptPubKey)) {
                signature = trans.calculateSignature(i, key, scriptPubKey, sigHash, anyoneCanPay);
                input.setScriptSig(ScriptBuilder.createInputScript(signature));
                input.setWitness(null);
            } else if (ScriptPattern.isP2PKH(scriptPubKey)) {
                signature = trans.calculateSignature(i, key, scriptPubKey, sigHash, anyoneCanPay);
                input.setScriptSig(ScriptBuilder.createInputScript(signature, key));
                input.setWitness(null);
            } else {
                if (!ScriptPattern.isP2WPKH(scriptPubKey)) {
                    throw new CryptoJException("Don't know how to sign for this kind of scriptPubKey: " + scriptPubKey);
                }
                Script scriptCode = ScriptBuilder.createP2PKHOutputScript(key);
                signature = trans.calculateWitnessSignature(i, key, scriptCode, input.getValue(), sigHash, anyoneCanPay);
                input.setScriptSig(ScriptBuilder.createEmpty());
                input.setWitness(TransactionWitness.redeemP2WPKH(signature, key));
            }
        }

        trans.verify();
        trans.getConfidence().setSource(TransactionConfidence.Source.SELF);
        trans.setPurpose(Transaction.Purpose.USER_PAYMENT);

        return Utils.HEX.encode(trans.bitcoinSerialize());
    }

    private static String doSignEthereumBasedTransaction(
            @NonNull String fromPrivateKey,
            @NonNull String toAddress,
            @NonNull Coin coin,
            @NonNull BigDecimal amount,
            @NonNull BigInteger nonce,
            @NonNull BigInteger gasPrice,
            @NonNull BigInteger gasLimit,
            @NonNull Boolean testnet
    ) {
        BigInteger value = amount.divide(coin.getMinValue()).toBigInteger();
        Long chainId = testnet ? 3L : 1L;
        Credentials credentials = Credentials.create(fromPrivateKey);
        RawTransaction rawTransaction = null;
        if (coin == Coin.ETH) {
            rawTransaction = RawTransaction.createEtherTransaction(
                    nonce,
                    gasPrice,
                    gasLimit,
                    toAddress,
                    value
            );
        } else {
            Function function = new Function("transfer", Arrays.asList(new org.web3j.abi.datatypes.Address(toAddress), new Uint256(value)), Arrays.asList(new TypeReference<Bool>() {
            }));
            String txData = FunctionEncoder.encode(function);
            org.web3j.protocol.core.methods.request.Transaction prepareTx = new org.web3j.protocol.core.methods.request.Transaction(
                    credentials.getAddress(),
                    nonce,
                    gasPrice,
                    null,
                    coin.getSmartContractAddress(),
                    BigInteger.ZERO,
                    txData
            );
            rawTransaction = RawTransaction.createTransaction(
                    Numeric.decodeQuantity(prepareTx.getNonce()),
                    Numeric.decodeQuantity(prepareTx.getGasPrice()),
                    gasLimit,
                    prepareTx.getTo(),
                    Numeric.decodeQuantity(prepareTx.getValue()),
                    prepareTx.getData()
            );
        }
        byte[] byteArray = TransactionEncoder.signMessage(rawTransaction, chainId, credentials);
        return Numeric.toHexString(byteArray);
    }

}
