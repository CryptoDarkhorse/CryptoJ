package cryptoj.oldimpl;

import io.tatum.constants.Constant;
import io.tatum.model.request.transaction.FromUTXO;
import io.tatum.model.request.transaction.To;
import io.tatum.model.request.transaction.TransferBtcBasedBlockchain;
import io.tatum.transaction.bitcoin.TransactionBuilder;
import lombok.NonNull;
import org.bitcoinj.core.NetworkParameters;

/**
 * Added just for demonstration purposes. // todo remove later, together with tatum dependency in pom.xml
 */
public class BtcSign {

    public static String sign(@NonNull FromUTXO[] fromUTXO, @NonNull To[] to, @NonNull Boolean testnet) {
        return prepareSignedTransaction(
                testnet,
                new TransferBtcBasedBlockchain(
                        null,
                        fromUTXO,
                        to
                )
        );
    }

    static String prepareSignedTransaction(boolean testnet, TransferBtcBasedBlockchain body) {
        FromUTXO[] fromUTXO = body.getFromUTXO();
        To[] to = body.getTo();
        NetworkParameters network = testnet ? Constant.BITCOIN_TESTNET : Constant.BITCOIN_MAINNET;
        TransactionBuilder transactionBuilder = new TransactionBuilder(network);
        To[] var8 = to;
        int var9 = to.length;
        int var10;
        for (var10 = 0; var10 < var9; ++var10) {
            To itemxx = var8[var10];
            transactionBuilder.addOutput(itemxx.getAddress(), itemxx.getValue());
        }
        FromUTXO[] var22 = fromUTXO;
        var9 = fromUTXO.length;
        for (var10 = 0; var10 < var9; ++var10) {
            FromUTXO itemx = var22[var10];
            transactionBuilder.addInput(itemx.getTxHash(), itemx.getIndex(), itemx.getPrivateKey());
        }
        return transactionBuilder.build().toHex();
    }

}
