package org.example.cryptotoolprojectdescription;

import com.google.common.base.Splitter;
import lombok.NonNull;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.example.cryptotoolprojectdescription.classes.TXReceiver;
import org.example.cryptotoolprojectdescription.classes.UTXObject;
import org.example.cryptotoolprojectdescription.enums.AddressType;
import org.example.cryptotoolprojectdescription.enums.Currency;
import org.example.cryptotoolprojectdescription.enums.NetType;
import org.example.cryptotoolprojectdescription.enums.Network;
import org.example.cryptotoolprojectdescription.exceptions.CryptoException;
import org.example.cryptotoolprojectdescription.network.IWrappedNetParams;
import org.example.cryptotoolprojectdescription.network.WrappedMainNetParams;
import org.example.cryptotoolprojectdescription.network.WrappedTestNetParams;
import org.jetbrains.annotations.NotNull;
import org.web3j.crypto.Keys;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class CryptoJ {

    /**
     * Generate valid mnemonic (seed) (accrodring to given attributes)
     *
     * @param length for example 12
     * @return mnemonic
     * @throws CryptoException if something goes wrong
     */
    public static String generateMnemonic(
            @NonNull Integer length
    ) throws CryptoException {
        // check word length
        if (length < 12 || length > 24 || length % 3 > 0)
            throw new CryptoException("Invalid word length: it must be between 12 and 24, and multiple of 3");

        int checkSumLen = length / 3;
        int entropyLen = length * 11 - checkSumLen;

        // Generate deterministic seed
        DeterministicSeed seed = new DeterministicSeed(new SecureRandom(), entropyLen, "");

        // Get mnemonic from seed
        List<String> words = seed.getMnemonicCode();

        // Concat word list
        String mnemonic = String.join(" ", words);

        return mnemonic;
    }

    /**
     * validate if mnemonic (seed) is ok (accrodring to given attributes)
     *
     * @param mnemonic seed
     * @return true if mnemonic is ok, otherwise false
     * @throws CryptoException
     */
    public static boolean isMnemonicValid(
            @NonNull String mnemonic
    ) throws CryptoException {
        // Split mnemonic string by space
        List<String> words = Splitter.on(' ').splitToList(mnemonic);

        // check by MnemonicCode class of BitcoinJ
        try {
            MnemonicCode.INSTANCE.check(words);
            return true;
        } catch (MnemonicException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static NetworkParameters getNetworkParams(Network network, NetType netType) {
        IWrappedNetParams wrappedParams = null;
        NetworkParameters params = null;

        if (netType.isMainNet()) {
            params = WrappedMainNetParams.get();
            wrappedParams = WrappedMainNetParams.get();
        } else {
            params = WrappedTestNetParams.get();
            wrappedParams = WrappedTestNetParams.get();
        }

        wrappedParams.setBIP32Headers(
                netType.getBech32(),
                netType.getPubKeyHash(),
                netType.getScriptHash(),
                netType.getWif(),
                netType.getP2pkhPub(),
                netType.getP2pkhPriv(),
                netType.getP2wpkhPub(),
                netType.getP2wpkhPriv()
        );

        return params;
    }

    /**
     * Generate extended public key for relevant network, nettype, and address type from given mnemonic
     * @param network
     * @param netType
     * @param addrType
     * @param mnemonic
     * @return extened public key
     * @throws CryptoException
     *
     * Note: Extended public key of LiteCoin have 2 kinds of prefixes - xpub & Ltpub
     *       However, this is only difference of notation, and results are same.
     *       And most LiteCoin wallets support all of these 2 types and toggle using a checkbox
     *       which has label "Use Ltpv / Ltub instead of xprv / xpub" or so.
     */
    public static String generateXPub(
            @NonNull Network network,
            @NonNull NetType netType,
            @NotNull AddressType addrType,
            @NonNull String mnemonic
    ) throws CryptoException {
        if (addrType.getPurpose() < 0) {
            throw new CryptoException("P2SH does not support HD wallet");
        }

        DeterministicSeed seed;
        try {
            seed = new DeterministicSeed(mnemonic, null, "", 0);
        } catch (UnreadableWalletException e) {
            throw new CryptoException("Invalid mnemonic");
        }

        /**
         * Build HD path
         * Ref: BIP 44 - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
         */
        HDPath path = HDPath.m();

        // extend purpose - current path is m/purpose'
        path = path.extend(new ChildNumber(addrType.getPurpose(), true)); // /purpose'

        // extend coin type - current path is m/purpose'/coin_type'
        if (netType.isMainNet()) {
            path = path.extend(new ChildNumber(netType.getCoinType(), true));
        } else {
            // purpose value of testnet is 1 for all coin types
            path = path.extend(new ChildNumber(1, true));
        }

        // extend account & change - m/purpose'/coin_type'/account'/change
        path = path.extend(new ChildNumber(0, true));
        path = path.extend(new ChildNumber(0, false));

        DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed).build();

        DeterministicKey key = chain.getKeyByPath(path, true);

        NetworkParameters params = getNetworkParams(network, netType);

        String encodedKey = "";
        if (addrType.equals(AddressType.P2PKH_LEGACY)) {
            encodedKey = key.serializePubB58(params, Script.ScriptType.P2PKH);
        } else {
            encodedKey = key.serializePubB58(params, Script.ScriptType.P2WPKH);
        }

        return encodedKey;
    }

    /**
     * Check if xpub is valid (accrodring to given attributes)
     *
     * @param network
     * @param netType
     * @param xPub
     * @return
     * @throws CryptoException
     */
    public static boolean isXPubValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NotNull AddressType addrType,
            @NonNull String xPub
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network, netType);

        try {
            DeterministicKey key = DeterministicKey.deserializeB58(xPub, params);
            if (key.isPubKeyOnly()) return true;
            return false; // extended private key
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * generate private key
     *
     * @param network
     * @param netType
     * @param mnemonic
     * @param derivationIndex
     * @return
     * @throws CryptoException
     */
    public static String generatePrivKey(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull AddressType addrType,
            @NonNull String mnemonic,
            @NonNull int derivationIndex
    ) throws CryptoException {
        if (addrType.getPurpose() < 0) {
            throw new CryptoException("P2SH does not support HD wallet");
        }

        DeterministicSeed seed;
        try {
            seed = new DeterministicSeed(mnemonic, null, "", 0);
        } catch (UnreadableWalletException e) {
            throw new CryptoException("Invalid mnemonic");
        }

        /**
         * Build HD path
         * Ref: BIP 44 - https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
         */
        HDPath path = HDPath.m();

        // extend purpose - m/purpose'
        path = path.extend(new ChildNumber(addrType.getPurpose(), true));

        // extend coin type - m/purpose'/coin_type'
        if (netType.isMainNet()) {
            path = path.extend(new ChildNumber(netType.getCoinType(), true));
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
        NetworkParameters params = getNetworkParams(network, netType);

        String encodedKey = "";
        switch (network) {
            case BITCOIN:
            case LITECOIN:
                encodedKey = key.getPrivateKeyAsWiF(params);
                break;
            case ETHEREUM:
                encodedKey = "0x" + key.getPrivateKeyAsHex();
                break;
            default:
                throw new CryptoException("Unsupported network");
        }
        return encodedKey;
    }

    /**
     * validate privatekey (accrodring to given attributes)
     *
     * @param network
     * @param netType
     * @param privKey
     * @return
     * @throws CryptoException
     */
    public static boolean isPrivKeyValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String privKey
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network, netType);

        if (network == Network.ETHEREUM) {
            privKey = privKey.toLowerCase();
            if (!privKey.startsWith("0x")) return false;

            try {
                byte[] privKeyBytes = Utils.HEX.decode(privKey.substring(2));
                ECKey.fromPrivate(privKeyBytes);
                return true;
            } catch (IllegalArgumentException ex) {
                ex.printStackTrace();
                return false;
            }
        }

        try {
            DumpedPrivateKey.fromBase58(params, privKey);
            return true;
        } catch (AddressFormatException ex) {
            ex.printStackTrace();
            System.err.println();
            return false;
        }
    }

    /**
     * generate address (accrodring to given attributes) to receive coins
     *
     * @param network
     * @param netType
     * @param xPub
     * @param derivationIndex
     * @return
     * @throws CryptoException
     */
    public static String generateAddress(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull AddressType addrType,
            @NonNull String xPub,
            @NonNull int derivationIndex
    ) throws CryptoException {
        if (!isXPubValid(network, netType, addrType, xPub)) {
            throw new CryptoException("Invalid xpub");
        }

        NetworkParameters params = getNetworkParams(network, netType);

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
                throw new CryptoException("P2SH does not support HD wallet");
            default:
                throw new CryptoException("Unsupported address type");
        }

        Address address = Address.fromKey(params, key, scryptType);

        String encodedAddress = "";
        switch (network) {
            case ETHEREUM:
                if (addrType == AddressType.P2PKH_LEGACY) {
                    byte[] encoded = key.getPubKeyPoint().getEncoded(false);
                    BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
                    return Keys.toChecksumAddress(Keys.getAddress(publicKey));
                }
            case BITCOIN:
            case LITECOIN:
                encodedAddress = address.toString();
                break;
            default:
                throw new CryptoException("Unsupported network");
        }
        return encodedAddress;
    }

    /**
     * validate if address is valid (accrodring to given attributes) and contains no errors mis-typos etc
     *
     * @param network
     * @param netType
     * @param address
     * @return
     * @throws CryptoException
     */
    public static boolean isAddressValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String address
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network, netType);

        if (network == Network.ETHEREUM && address.startsWith("0x")) {
            // ethereum legacy address
            return Utils.HEX.canDecode(address.toLowerCase().substring(2)) && // only hexadecimal characters
                    address.length() == 42; // 20bytes + "0x" = 42 characters
        }

        try {
            Address.fromString(params, address);
            return true;
        } catch (AddressFormatException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    /**
     * generate signed transaction which is ready to be broadcasted. It needs to support all possible AddressTypes in input/output
     *
     * @param network
     * @param netType
     * @param utxobjects
     * @param txReceivers
     * @return
     * @throws CryptoException
     */
    public String signBTCLTCBasedTransaction(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoException {
        throw new CryptoException("Not Implemented");
    }

    // IMPLEMENTED METHODS //

    public String generateSignedBitcoinBasedTransaction(
            @NonNull Currency currency,
            @NonNull NetType netType,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoException {
        Network network = currency.getNetwork();
        if (network != Network.BITCOIN && network != Network.LITECOIN) {
            throw new CryptoException("This method can't be used on " + network.getName() + " network.");
        }
        for (UTXObject utxo : utxobjects) {
            utxo.setTxHash(utxo.getTxHash().replace(" ", ""));
            if (utxo.getTxHash().isEmpty()) {
                throw new CryptoException("Invalid UTXO txHash.");
            }
            if (utxo.getIndex() < 0) {
                throw new CryptoException("Invalid UTXO index.");
            }
            utxo.setPrivKey(utxo.getPrivKey().replace(" ", ""));
            if (isPrivKeyValid(network, netType, utxo.getPrivKey()) == false) {
                throw new CryptoException("Sender's private key " + utxo.getPrivKey() + " for TxId=" + utxo.getTxHash() + " Index=" + utxo.getIndex() + " is invalid.");
            }
        }
        for (TXReceiver txReceiver : txReceivers) {
            txReceiver.setAddress(txReceiver.getAddress().replace(" ", ""));
            if (isAddressValid(network, netType, txReceiver.getAddress()) == false) {
                throw new CryptoException("Receiver's address " + txReceiver.getAddress() + " is invalid.");
            }
            BigDecimal amount = txReceiver.getAmount().stripTrailingZeros();
            int scale = currency.getScale();
            RoundingMode rm = RoundingMode.DOWN;
            if (amount.setScale(scale, rm).compareTo(amount) != 0) {
                throw new CryptoException("Invalid amount scale.");
            }
            amount = amount.setScale(scale, rm);

            if (amount.compareTo(currency.getMinValue()) < 0) {
                throw new CryptoException("Receiver's amount " + amount + " is less than min " + currency.getMinValue() + " " + currency.getCode() + ".");
            }
            txReceiver.setAmount(amount);
        }
        return signBTCLTCBasedTransaction(
                network,
                netType,
                utxobjects,
                txReceivers
        );
    }

    public String generateSignedEthereumBasedTransaction(
            @NonNull NetType netType,
            @NonNull String fromPrivateKey,
            @NonNull String toAddress,
            @NonNull BigDecimal amount, // absolute amount, for example 0.123456789012345678 ETH
            @NonNull Currency currency,
            @NonNull BigInteger nonce,
            @NonNull BigInteger gasPriceInETHWei, // for example value 'gasPriceInETHWei=150' means '150wei', which is 0.000000000000000150 ETH
            @NonNull BigInteger gasLimitInUnits // for example 20000
    ) throws CryptoException {
        Network network = currency.getNetwork();
        if (network != Network.ETHEREUM) {
            throw new CryptoException("This method can't be used on " + network.getName() + " network.");
        }
        fromPrivateKey = fromPrivateKey.replace(" ", "");
        if (isPrivKeyValid(network, netType, fromPrivateKey) == false) {
            throw new CryptoException("Private key is invalid.");
        }
        toAddress = toAddress.replace(" ", "");
        if (isAddressValid(network, netType, toAddress) == false) {
            throw new CryptoException("To address is invalid.");
        }
        amount = amount.stripTrailingZeros();
        int scale = currency.getScale();
        RoundingMode rm = RoundingMode.DOWN;
        if (amount.setScale(scale, rm).compareTo(amount) != 0) {
            throw new CryptoException("Invalid amount scale.");
        }
        amount = amount.setScale(scale, rm);
        if (amount.compareTo(currency.getMinValue()) < 0) {
            throw new CryptoException("Amount is less than min " + currency.getMinValue() + " " + currency.getCode() + ".");
        }
        if (nonce.compareTo(BigInteger.ZERO) < 0) {
            throw new CryptoException("Invalid nonce. Must be greater or equal to zero.");
        }
        if (gasPriceInETHWei.compareTo(BigInteger.ZERO) <= 0) {
            throw new CryptoException("Invalid gas price in wei. Must be greater than zero.");
        }
        if (gasLimitInUnits.compareTo(BigInteger.ZERO) <= 0) {
            throw new CryptoException("Invalid gas limit in units. Must be greater than zero.");
        }
        return signEthBasedTransaction(
                fromPrivateKey,
                toAddress,
                currency,
                amount,
                nonce,
                gasPriceInETHWei,
                gasLimitInUnits,
                !netType.isMainNet()
        );
    }

    String signEthBasedTransaction(
            @NonNull String fromPrivateKey,
            @NonNull String toAddress,
            @NonNull Currency currency,
            @NonNull BigDecimal amount,
            @NonNull BigInteger nonce,
            @NonNull BigInteger gasPrice,
            @NonNull BigInteger gasLimit,
            @NonNull Boolean testnet
    ) {
        /*
        BigInteger value = amount.divide(currency.getMinValue()).toBigInteger();
        Long chainId = testnet ? 3L : 1L;
        Credentials credentials = Credentials.create(fromPrivateKey);
        RawTransaction rawTransaction = null;
        if (currency == Currency.ETH) {
            rawTransaction = RawTransaction.createEtherTransaction(
                    nonce,
                    gasPrice,
                    gasLimit,
                    toAddress,
                    value
            );
        } else {
            Function function = new Function("transfer", Arrays.asList(new Address(toAddress), new Uint256(value)), Arrays.asList(new TypeReference<Bool>() {
            }));
            String txData = FunctionEncoder.encode(function);
            Transaction prepareTx = new Transaction(
                    credentials.getAddress(),
                    nonce,
                    gasPrice,
                    null,
                    currency.getSmartContractAddress(),
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
        */
        return "";
    }

}
