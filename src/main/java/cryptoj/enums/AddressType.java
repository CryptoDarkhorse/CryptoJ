package cryptoj.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum AddressType {

    // BIP44 - Multi-Account Hierarchy for Deterministic Wallets
    P2PKH_LEGACY("P2PKH_LEGACY", "P2PKH (Legacy)", 44), // BIP44

    // P2SH
    P2SH_PAY_TO_SCRIPT_HASH("P2SH_PAY_TO_SCRIPT_HASH", "P2SH (Pay-To-Script-Hash)", -1),

    // BIP84 - Derivation scheme for P2WPKH based accounts
    // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
    P2WPKH_NATIVE_SEGWIT("P2WPKH_NATIVE_SEGWIT", "P2WPKH (Native SegWit)", 84),

    // BIP86 - Key Derivation for Single Key P2TR Outputs
    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    P2TR_TAPROOT("P2TR_TAPROOT", "P2TR (Taproot)", 86);

    final String code;
    final String name;
    final Integer purpose; // BIP44 key derivation path - purpose field

    AddressType(
            final @NonNull String code,
            final @NonNull String name,
            final @NonNull Integer purpose
    ) {
        this.code = code;
        this.name = name;
        this.purpose = purpose;
    }

}
