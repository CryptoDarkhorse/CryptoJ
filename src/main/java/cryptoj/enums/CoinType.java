package cryptoj.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum CoinType {

    BTC("BTC","Bitcoin"),
    ETH("ETH","Ethereum"),
    LTC("LTC", "Litecoin");

    final String code;
    final String name;

    CoinType(
            final @NonNull String code,
            final @NonNull String name
    ) {
        this.code = code;
        this.name = name;
    }

}
