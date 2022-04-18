package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum TokenType {

    ERC20("ERC20", "ERC20");

    final String code;
    final String name;

    TokenType(
            final @NonNull String code,
            final @NonNull String name
    ) {
        this.code = code;
        this.name = name;
    }

}
