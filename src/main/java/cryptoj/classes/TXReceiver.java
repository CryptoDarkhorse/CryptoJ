package cryptoj.classes;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;

import static lombok.AccessLevel.PRIVATE;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@FieldDefaults(level = PRIVATE)
public class TXReceiver {

    @NonNull String address;
    @NonNull BigDecimal amount; // absolute value, for example 0.1 BTC or 0.12345678 LTC

    public TXReceiver(
            @NonNull String address,
            @NonNull double amount
    ) {
        this.address = address;
        this.amount = new BigDecimal(amount);
    }

}
