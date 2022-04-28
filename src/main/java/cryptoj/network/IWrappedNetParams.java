package cryptoj.network;

public interface IWrappedNetParams {
    void setBIP32Headers(
            final String bech32,
            final int pubKeyHash,
            final int scriptHash,
            final int wif,
            final int p2pkhPub,
            final int p2pkhPriv,
            final int p2wpkhPub,
            final int p2wpkhPriv
    );
}
