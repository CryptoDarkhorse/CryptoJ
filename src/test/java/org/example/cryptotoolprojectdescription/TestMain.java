package org.example.cryptotoolprojectdescription;

import org.bitcoinj.wallet.DeterministicSeed;
import org.example.cryptotoolprojectdescription.exceptions.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.List;

public class TestMain {
    @Test
    @DisplayName("Testing mnemonic generation & validation")
    void testMnemonic() {
        try {
            String generated = ICryptoTool.generateMnemonic(12);
            assertTrue(ICryptoTool.isMnemonicValid(generated));

            String validMnemonic = "clap shove riot taxi vessel achieve echo swift ripple blush rate census sick exit dry make adult swing";
            assertTrue(ICryptoTool.isMnemonicValid(validMnemonic));
        } catch (CryptoException e) {
            assertTrue(false, "Invalid CryptoException catched");
        }
    }
}
