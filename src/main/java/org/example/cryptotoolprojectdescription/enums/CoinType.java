package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum CoinType {

    BTC("BITCOIN","Bitcoin"),
    ETH("ETHEREUM","Ethereum"),
    LTC("LITECOIN", "Litecoin");

    final String code;
    final String name;

    CoinType(
            final @NonNull String code,
            final @NonNull String name
    ) {
        this.code = code;
        this.name = name;
    }

    public String getNameInLowerCase() {
        return name.toLowerCase();
    }

}
