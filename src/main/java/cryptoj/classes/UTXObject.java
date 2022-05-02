package cryptoj.classes;

import lombok.*;
import lombok.experimental.FieldDefaults;

import static lombok.AccessLevel.PRIVATE;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@FieldDefaults(level = PRIVATE)
public class UTXObject {

    @NonNull String txHash;
    @NonNull Long index;
    @NonNull String privKey;
    String txRawData;

    public UTXObject(@NonNull  String txHash, @NonNull Long index, @NonNull String privKey) {
        this.txHash = txHash;
        this.index = index;
        this.privKey = privKey;
        txRawData = null;
    }

}
