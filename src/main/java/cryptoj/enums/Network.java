package cryptoj.enums;

import lombok.Getter;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum Network {
    BITCOIN_MAINNET(
            CoinType.BTC, true,0,
            "bc", 0x00, 0x05, 0x80,
            0x0488B21E,     // xpub
            0x0488ADE4,     // xprv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    BITCOIN_TESTNET(
            CoinType.BTC, false,1,
            "tb", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x045f1cf6,    // vpub
            0x045f18bc     // vprv
    ),
    BITCOIN_REGTEST(
            CoinType.BTC, false,1,
            "bcrt", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x045f1cf6,    // vpub
            0x045f18bc     // vprv
    ),
    ETHEREUM_MAINNET(
            CoinType.ETH, true,60,
            "bc", 0x00, 0x05, 0x80,
            0x0488B21E,     // xpub
            0x0488ADE4,     // xprv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    ETHEREUM_TESTNET_ROPSTEN( // todo use real values to be able to use ROPSTEN testnet network as well
            CoinType.ETH, false,60,
            "bc", 0x00, 0x05, 0x80,
            0x0488B21E,     // xpub
            0x0488ADE4,     // xprv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    LITECOIN_MAINNET(
            CoinType.LTC, true,2,
            "ltc", 0x30, 0x32, 0xb0,
            0x019da462,     // Ltub
            0x019d9cfe,     // Ltpv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    LITECOIN_TESTNET(
            CoinType.LTC, false,1,
            "tltc", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x043587cf,    // tpub
            0x04358394     // tprv
    );

    final CoinType coinType; // network code - matched with Network.code
    final boolean isMainNet;
    final int coinId; // BIP44 coin_id - https://github.com/satoshilabs/slips/blob/master/slip-0044.md

    // Base58 encoding version numbers
    final String bech32;
    final int pubKeyHash;
    final int scriptHash;
    final int wif;
    final int p2pkhPub;
    final int p2pkhPriv;
    final int p2wpkhPub;
    final int p2wpkhPriv;

    Network(
            final CoinType coinType,
            final boolean isMainNet,
            final int coinId,
            final String bech32,
            final int pubKeyHash,
            final int scriptHash,
            final int wif,
            final int p2pkhPub,
            final int p2pkhPriv,
            final int p2wpkhPub,
            final int p2wpkhPriv
    ) {
        this.coinType = coinType;
        this.isMainNet = isMainNet;
        this.coinId = coinId;
        this.bech32 = bech32;
        this.pubKeyHash = pubKeyHash;
        this.scriptHash = scriptHash;
        this.wif = wif;
        this.p2pkhPub = p2pkhPub;
        this.p2pkhPriv = p2pkhPriv;
        this.p2wpkhPub = p2wpkhPub;
        this.p2wpkhPriv = p2wpkhPriv;
    }
}
