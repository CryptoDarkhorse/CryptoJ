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
     * @param amount  absolute value in full units. For example 0.1 BTC or 1.12345678 LTC
     */
    public TXReceiver(
            @NonNull String address,
            @NonNull BigDecimal amount
    ) {
        this.address = address.trim();
        this.amount = amount;
        if (this.address.isEmpty()) {
            throw new IllegalArgumentException("Invalid address.");
        }
        if (this.amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Invalid amount.");
        }
    }

    /**
     * Definition of receiver of coins.
     *
     * @param address of the receiver
     * @param amount  absolute value in full units. For example 0.1 BTC or 1.12345678 LTC
     */
    public TXReceiver(
            @NonNull String address,
            @NonNull double amount
    ) {
        this.address = address.trim();
        this.amount = new BigDecimal(amount);
        if (this.address.isEmpty()) {
            throw new IllegalArgumentException("Invalid address.");
        }
        if (this.amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Invalid amount.");
        }
    }

}
