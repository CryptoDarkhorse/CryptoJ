package cryptoj.tools;

import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import java.security.SecureRandom;
import java.util.Random;

import static lombok.AccessLevel.PRIVATE;

@FieldDefaults(level = PRIVATE)
public class StringTools {


    public static final String NUMERIC_ARRAY = "0123456789";
    public static final String ALPHABETICAL_ARRAY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String ALPHANUMERIC_ARRAY = NUMERIC_ARRAY + ALPHABETICAL_ARRAY;
    public static final String ALPHANUMERIC_CASE_SENSITIVE_ARRAY = ALPHANUMERIC_ARRAY + ALPHABETICAL_ARRAY.toLowerCase();

    public static String generateRandomString(@NonNull Integer length, @NonNull String arrayOfSymbols) {
        if (length < 1) {
            throw new IllegalArgumentException("Length must be at least 1 or more.");
        }
        if (arrayOfSymbols.length() < 2) {
            throw new IllegalArgumentException("TArray of symbols is too short (min 2).");
        }
        Random random = new SecureRandom();
        char[] symbolsCharArray = arrayOfSymbols.toCharArray();
        char[] buffer = new char[length];
        for (int idx = 0; idx < buffer.length; ++idx) {
            buffer[idx] = symbolsCharArray[random.nextInt(symbolsCharArray.length)];
        }
        return new String(buffer);
    }


}
