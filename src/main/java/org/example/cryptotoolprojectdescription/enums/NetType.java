package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum NetType {
    BITCOIN(
            "BITCOIN", true,0,
            "bc", 0x00, 0x05, 0x80,
            0x0488B21E,     // xpub
            0x0488ADE4,     // xprv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    BITCOIN_TESTNET(
            "BITCOIN", false,1,
            "tb", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x045f1cf6,    // vpub
            0x045f18bc     // vprv
    ),
    BITCOIN_REGTEST(
            "BITCOIN", false,1,
            "bcrt", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x045f1cf6,    // vpub
            0x045f18bc     // vprv
    ),
    ETHEREUM(
            "ETHEREUM", true,60,
            "bc", 0x00, 0x05, 0x80,
            0x0488B21E,     // xpub
            0x0488ADE4,     // xprv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    LITECOIN(
            "LITECOIN", true,2,
            "ltc", 0x30, 0x32, 0xb0,
            0x019da462,     // Ltub
            0x019d9cfe,     // Ltpv
            0x04b24746,    // zpub
            0x04b2430c     // zprv
    ),
    LITECOIN_TESTNET(
            "LITECOIN", false,1,
            "litecointestnet", 0x6f, 0xc4, 0xef,
            0x043587cf,     // tpub
            0x04358394,     // tprv
            0x043587cf,    // tpub
            0x04358394     // tprv
    );

    final String netCode; // network code - matched with Network.code
    final boolean isMainNet;
    final int coinType; // BIP44 coin type - https://github.com/satoshilabs/slips/blob/master/slip-0044.md

    // Base58 encoding version numbers
    final String bech32;
    final int pubKeyHash;
    final int scriptHash;
    final int wif;
    final int p2pkhPub;
    final int p2pkhPriv;
    final int p2wpkhPub;
    final int p2wpkhPriv;

    NetType(
            final String netCode,
            final boolean isMainNet,
            final int coinType,
            final String bech32,
            final int pubKeyHash,
            final int scriptHash,
            final int wif,
            final int p2pkhPub,
            final int p2pkhPriv,
            final int p2wpkhPub,
            final int p2wpkhPriv
    ) {
        this.netCode = netCode;
        this.isMainNet = isMainNet;
        this.coinType = coinType;
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
