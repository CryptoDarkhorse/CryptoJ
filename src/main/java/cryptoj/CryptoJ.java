package cryptoj;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;
import cryptoj.classes.TXReceiver;
import cryptoj.classes.UTXObject;
import cryptoj.enums.AddressType;
import cryptoj.enums.Coin;
import cryptoj.enums.CoinType;
import cryptoj.enums.Network;
import cryptoj.exceptions.CryptoException;
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
import org.jetbrains.annotations.NotNull;
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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

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

    public static NetworkParameters getNetworkParams(Network network) {
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

    /**
     * Generate extended public key for relevant network, nettype, and address type from given mnemonic
     * @param network
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
     * @param xPub
     * @return
     * @throws CryptoException
     */
    public static boolean isXPubValid(
            @NonNull Network network,
            @NotNull AddressType addrType,
            @NonNull String xPub
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network);

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
     * @param mnemonic
     * @param derivationIndex
     * @return
     * @throws CryptoException
     */
    public static String generatePrivKey(
            @NonNull Network network,
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

        String encodedKey = "";
        switch (network.getCoinType()) {
            case BTC:
            case LTC:
                encodedKey = key.getPrivateKeyAsWiF(params);
                break;
            case ETH:
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
     * @param privKey
     * @return
     * @throws CryptoException
     */
    public static boolean isPrivKeyValid(
            @NonNull Network network,
            @NonNull String privKey
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network);

        if (network.getCoinType() == CoinType.ETH) {
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
     * @param xPub
     * @param derivationIndex
     * @return
     * @throws CryptoException
     */
    public static String generateAddress(
            @NonNull Network network,
            @NonNull AddressType addrType,
            @NonNull String xPub,
            @NonNull int derivationIndex
    ) throws CryptoException {
        if (!isXPubValid(network, addrType, xPub)) {
            throw new CryptoException("Invalid xpub");
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
                throw new CryptoException("P2SH does not support HD wallet");
            default:
                throw new CryptoException("Unsupported address type");
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
                throw new CryptoException("Unsupported network");
        }
        return encodedAddress;
    }

    /**
     * validate if address is valid (accrodring to given attributes) and contains no errors mis-typos etc
     *
     * @param network
     * @param address
     * @return
     * @throws CryptoException
     */
    public static boolean isAddressValid(
            @NonNull Network network,
            @NonNull String address
    ) throws CryptoException {
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
            ex.printStackTrace();
            return false;
        }
    }

    private static Transaction getParentTransaction(Network network, String txHash) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(new URI("https://api-eu1.tatum.io/v3/blockchain/node/" + network.getCoinType().getCode()))
                    .header("X-API-KEY", "ba638a01-3a6d-4fa3-b15b-4f395d9b90a4") // Tatum API key
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\n" +
                            "\"jsonrpc\": \"2.0\",\n" +
                            "\"method\": \"getrawtransaction\",\n" +
                            "\"params\": [ \n" +
                            "\"" + txHash + "\"],\n" +
                            "\"id\": 2\n" +
                            "}"))
                    .build();

            HttpResponse<String> response = HttpClient.newBuilder().build().send(req, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode node = mapper.readTree(response.body());
                String rawTransHex = node.get("result").asText();

                if (rawTransHex.equals("null")) {
                    System.err.println("Not found");
                    return null;
                }

                return new Transaction(getNetworkParams(network), Utils.HEX.decode(rawTransHex));
            } else {
                System.err.println("Fetching failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * generate signed transaction which is ready to be broadcasted. It needs to support all possible AddressTypes in input/output
     *
     * @param network
     * @param utxobjects
     * @param txReceivers
     * @return
     * @throws CryptoException
     */
    public static String signBTCLTCBasedTransaction(
            @NonNull Network network,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoException {
        NetworkParameters params = getNetworkParams(network);

        Context.getOrCreate(params);

        // Init transaction
        Transaction trans = new Transaction(params);
        trans.setVersion(2);

        // Add inputs
        for (int i = 0; i < utxobjects.length; i++) {
            UTXObject utxo = utxobjects[i];
            // get transaction data from txHash
            Transaction prevTrans = getParentTransaction(network, utxo.getTxHash());

            if (prevTrans == null) {
                throw new CryptoException("Failed to get UTXO info from blockchain");
            }

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
                input.setWitness((TransactionWitness)null);
            } else if (ScriptPattern.isP2PKH(scriptPubKey)) {
                signature = trans.calculateSignature(i, key, scriptPubKey, sigHash, anyoneCanPay);
                input.setScriptSig(ScriptBuilder.createInputScript(signature, key));
                input.setWitness((TransactionWitness)null);
            } else {
                if (!ScriptPattern.isP2WPKH(scriptPubKey)) {
                    throw new CryptoException("Don't know how to sign for this kind of scriptPubKey: " + scriptPubKey);
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

    // IMPLEMENTED METHODS //

    public static String generateSignedBitcoinBasedTransaction(
            @NonNull Coin coin,
            @NonNull Network network,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoException {
        CoinType coinType = coin.getCoinType();
        if (coinType != CoinType.BTC && coinType != CoinType.LTC) {
            throw new CryptoException("This method can't be used on " + coinType.getName() + " network.");
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
            if (isPrivKeyValid(network, utxo.getPrivKey()) == false) {
                throw new CryptoException("Sender's private key " + utxo.getPrivKey() + " for TxId=" + utxo.getTxHash() + " Index=" + utxo.getIndex() + " is invalid.");
            }
        }
        for (TXReceiver txReceiver : txReceivers) {
            txReceiver.setAddress(txReceiver.getAddress().replace(" ", ""));
            if (isAddressValid(network, txReceiver.getAddress()) == false) {
                throw new CryptoException("Receiver's address " + txReceiver.getAddress() + " is invalid.");
            }
            BigDecimal amount = txReceiver.getAmount().stripTrailingZeros();
            int scale = coin.getScale();
            RoundingMode rm = RoundingMode.DOWN;
//            if (amount.setScale(scale, rm).compareTo(amount) == 0) {
//                throw new CryptoException("Invalid amount scale.");
//            }
            amount = amount.setScale(scale, rm);

            if (amount.compareTo(coin.getMinValue()) < 0) {
                throw new CryptoException("Receiver's amount " + amount + " is less than min " + coin.getMinValue() + " " + coin.getCode() + ".");
            }
            txReceiver.setAmount(amount);
        }
        return signBTCLTCBasedTransaction(
                network,
                utxobjects,
                txReceivers
        );
    }

    public String generateSignedEthereumBasedTransaction(
            @NonNull Network network,
            @NonNull String fromPrivateKey,
            @NonNull String toAddress,
            @NonNull BigDecimal amount, // absolute amount, for example 0.123456789012345678 ETH
            @NonNull Coin coin,
            @NonNull BigInteger nonce,
            @NonNull BigInteger gasPriceInETHWei, // for example value 'gasPriceInETHWei=150' means '150wei', which is 0.000000000000000150 ETH
            @NonNull BigInteger gasLimitInUnits // for example 20000
    ) throws CryptoException {
        CoinType coinType = coin.getCoinType();
        if (coinType != CoinType.ETH) {
            throw new CryptoException("This method can't be used on " + coinType.getName() + " network.");
        }
        fromPrivateKey = fromPrivateKey.replace(" ", "");
        if (isPrivKeyValid(network, fromPrivateKey) == false) {
            throw new CryptoException("Private key is invalid.");
        }
        toAddress = toAddress.replace(" ", "");
        if (isAddressValid(network, toAddress) == false) {
            throw new CryptoException("To address is invalid.");
        }
        amount = amount.stripTrailingZeros();
        int scale = coin.getScale();
        RoundingMode rm = RoundingMode.DOWN;
        if (amount.setScale(scale, rm).compareTo(amount) != 0) {
            throw new CryptoException("Invalid amount scale.");
        }
        amount = amount.setScale(scale, rm);
        if (amount.compareTo(coin.getMinValue()) < 0) {
            throw new CryptoException("Amount is less than min " + coin.getMinValue() + " " + coin.getCode() + ".");
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
                coin,
                amount,
                nonce,
                gasPriceInETHWei,
                gasLimitInUnits,
                !network.isMainNet()
        );
    }

    String signEthBasedTransaction(
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
