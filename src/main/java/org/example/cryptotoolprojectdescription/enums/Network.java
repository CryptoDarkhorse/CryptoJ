package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum Network {

    BITCOIN("BITCOIN","Bitcoin"),
    ETHEREUM("ETHEREUM","Ethereum"),
    LITECOIN("LITECOIN", "Litecoin");

    final String code;
    final String name;

    Network(
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
