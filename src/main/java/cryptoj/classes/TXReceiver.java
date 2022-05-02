package cryptoj.classes;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;

import static lombok.AccessLevel.PRIVATE;

@Getter
@Setter
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@FieldDefaults(level = PRIVATE)
public class TXReceiver {

    @NonNull String address;
    @NonNull BigDecimal amount;

    /**
     * Definition of receiver of coins.
     *
     * @param address of the receiver
     * @param amount absolute value in full units. For example 0.1 BTC or 1.12345678 LTC
     */
    public TXReceiver(
            @NonNull String address,
            @NonNull BigDecimal amount
    ) {
        this.address = address;
        this.amount = amount;
    }

    /**
     * Definition of receiver of coins.
     *
     * @param address of the receiver
     * @param amount absolute value in full units. For example 0.1 BTC or 1.12345678 LTC
     */
    public TXReceiver(
            @NonNull String address,
            @NonNull double amount
    ) {
        this.address = address;
        this.amount = new BigDecimal(amount);
    }

}
