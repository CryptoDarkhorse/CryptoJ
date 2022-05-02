package cryptoj.classes;

import lombok.*;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@Setter
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@FieldDefaults(level = PRIVATE)
public class UTXObject {

    @NonNull String txRawData;
    @NonNull Long index;
    @NonNull String privKey;

    /**
     * Definition of sender.
     *
     * @param txRawData full raw hex data of UTXO
     * @param index index to spent from
     * @param privKey private key of address of the index
     */
    public UTXObject(
            @NonNull String txRawData,
            @NonNull Long index,
            @NonNull String privKey
    ) {
        this.txRawData = txRawData.trim();
        this.index = index;
        this.privKey = privKey.trim();
        if (this.txRawData.isEmpty()) {
            throw new IllegalArgumentException("Invalid tx raw data.");
        }
        if (this.index < 0) {
            throw new IllegalArgumentException("Invalid index.");
        }
        if (this.privKey.isEmpty()) {
            throw new IllegalArgumentException("Invalid priv key.");
        }
    }

}
