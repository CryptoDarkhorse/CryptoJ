package cryptoj.network;

import org.bitcoinj.params.TestNet3Params;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class WrappedTestNetParams extends TestNet3Params implements IWrappedNetParams {

    private static WrappedTestNetParams instance;

    /**
     * Get ltc main net params.
     *
     * @return the ltc main net params
     */
    public static synchronized WrappedTestNetParams get() {
        if (instance == null) {
            instance = new WrappedTestNetParams();
        }
        return instance;
    }

    // Change BIP32 headers for different coins
    @Override
    public void setBIP32Headers(
            final String bech32,
            final int pubKeyHash,
            final int scriptHash,
            final int wif,
            final int p2pkhPub,
            final int p2pkhPriv,
            final int p2wpkhPub,
            final int p2wpkhPriv
    ) {
        this.segwitAddressHrp = bech32;
        this.addressHeader = pubKeyHash;
        this.p2shHeader = scriptHash;
        this.dumpedPrivateKeyHeader = wif;
        this.bip32HeaderP2PKHpub = p2pkhPub;
        this.bip32HeaderP2PKHpriv = p2pkhPriv;
        this.bip32HeaderP2WPKHpub = p2wpkhPub;
        this.bip32HeaderP2WPKHpriv = p2wpkhPriv;
    }

}
