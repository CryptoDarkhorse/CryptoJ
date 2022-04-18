package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum AddressType {

    P2PKH_LEGACY("P2PKH_LEGACY", "P2PKH (Legacy)"),
    P2SH_PAY_TO_SCRIPT_HASH("P2SH_PAY_TO_SCRIPT_HASH", "P2SH (Pay-To-Script-Hash)"),
    P2WPKH_NATIVE_SEGWIT("P2WPKH_NATIVE_SEGWIT", "P2WPKH (Native SegWit)"),
    P2TR_TAPROOT("P2TR_TAPROOT", "P2TR (Taproot)");

    final String code;
    final String name;

    AddressType(
            final @NonNull String code,
            final @NonNull String name
    ) {
        this.code = code;
        this.name = name;
    }

}
