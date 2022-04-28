package cryptoj.exceptions;

public class CryptoJException extends Exception {

    public CryptoJException() {
        super();
    }

    public CryptoJException(String message) {
        super(message);
    }

    public CryptoJException(Throwable cause) {
        super(cause);
    }

    public CryptoJException(String message, Throwable cause) {
        super(message, cause);
    }

}
