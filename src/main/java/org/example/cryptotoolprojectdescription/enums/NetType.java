package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum NetType {

    MAINNET("MAINNET", "Mainnet"),
    TESTNET("TESTNET", "Testnet");

    final String code;
    final String name;

    NetType(
            final @NonNull String code,
            final @NonNull String name
    ) {
        this.code = code;
        this.name = name;
    }

}
