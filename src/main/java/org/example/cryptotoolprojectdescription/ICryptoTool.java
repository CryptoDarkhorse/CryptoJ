package org.example.cryptotoolprojectdescription;

import lombok.NonNull;
import org.example.cryptotoolprojectdescription.classes.TXReceiver;
import org.example.cryptotoolprojectdescription.classes.UTXObject;
import org.example.cryptotoolprojectdescription.enums.AddressType;
import org.example.cryptotoolprojectdescription.enums.Currency;
import org.example.cryptotoolprojectdescription.enums.NetType;
import org.example.cryptotoolprojectdescription.enums.Network;
import org.example.cryptotoolprojectdescription.exceptions.CryptoException;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.utils.Numeric;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.List;

public abstract class ICryptoTool {

    /**
     * Generate valid mnemonic (seed) (accrodring to given attributes)
     *
     * @param listOfAllWords dictionary which will be used to generate the mnemonic
     * @param length for example 12
     * @return mnemonic
     * @throws CryptoException if something goes wrong
     */
    public abstract String generateMnemonic(
            @NonNull List<String> listOfAllWords,
            @NonNull Integer length
    ) throws CryptoException;

    /**
     * validate if mnemonic (seed) is ok (accrodring to given attributes)
     *
     * @param mnemonic seed
     * @return true if mnemonic is ok, otherwise false
     * @throws CryptoException
     */
    public abstract boolean isMnemonicValid(
            @NonNull String mnemonic
    ) throws CryptoException;

    /**
     * Generate xpub (accrodring to given attributes) for relevant network and nettype from given mnemonic
     *
     * @param network
     * @param netType
     * @param mnemonic
     * @return
     * @throws CryptoException
     */
    public abstract String generateXPub(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String mnemonic
    ) throws CryptoException;

    /**
     * Check if xpub is valid (accrodring to given attributes)
     *
     * @param network
     * @param netType
     * @param xPub
     * @return
     * @throws CryptoException
     */
    public abstract boolean isXPubValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String xPub
    ) throws CryptoException;

    /**
     * generate address (accrodring to given attributes) to receive coins
     *
     * @param network
     * @param netType
     * @param xPub
     * @param derivationIndex
     * @param addressType
     * @return
     * @throws CryptoException
     */
    public abstract String generateAddress(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String xPub,
            @NonNull Long derivationIndex,
            AddressType addressType
    ) throws CryptoException;

    /**
     * validate if address is valid (accrodring to given attributes) and contains no errors mis-typos etc
     *
     * @param network
     * @param netType
     * @param address
     * @param addressType
     * @return
     * @throws CryptoException
     */
    public abstract boolean isAddressValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String address,
            AddressType addressType
    ) throws CryptoException;

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
    public abstract String generatePrivKey(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String mnemonic,
            @NonNull Long derivationIndex
    ) throws CryptoException;

    /**
     * validate privatekey (accrodring to given attributes)
     *
     * @param network
     * @param netType
     * @param privKey
     * @return
     * @throws CryptoException
     */
    public abstract boolean isPrivKeyValid(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull String privKey
    ) throws CryptoException;

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
    public abstract String signBTCLTCBasedTransaction(
            @NonNull Network network,
            @NonNull NetType netType,
            @NonNull UTXObject[] utxobjects,
            @NonNull TXReceiver[] txReceivers
    ) throws CryptoException;

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
            if (isAddressValid(network, netType, txReceiver.getAddress(), null) == false) {
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
        if (isAddressValid(network, netType, toAddress, null) == false) {
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
                netType == NetType.TESTNET
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
    }

}
