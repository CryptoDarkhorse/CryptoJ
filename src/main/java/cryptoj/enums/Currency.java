package cryptoj.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum Currency {

    AA1(
            "AA1",
            "AA1Token",
            "AA1",
            18,
            CoinType.ETH,
            new BigDecimal("0.000000000000000001"),
            Set.of(Network.ETHEREUM),
            TokenType.ERC20,
            "0x9b8b16c5868a41eb9bb033dd271b3c68719f84a7",
            new BigDecimal("20")
    ),
    BTC(
            "BTC",
            "Bitcoin",
            "BTC",
            8,
            CoinType.BTC,
            new BigDecimal("0.00000001"),
            Set.of(Network.BITCOIN, Network.BITCOIN_TESTNET, Network.BITCOIN_REGTEST),
            null,
            null,
            null
    ),
    ETH(
            "ETH",
            "Ethereum",
            "ETH",
            18,
            CoinType.ETH,
            new BigDecimal("0.000000000000000001"),
            Set.of(Network.ETHEREUM),
            null,
            null,
            null
    ),
    LTC(
            "LTC",
            "Litecoin",
            "LTC",
            8,
            CoinType.LTC,
            new BigDecimal("0.00000001"),
            Set.of(Network.LITECOIN, Network.LITECOIN_TESTNET),
            null,
            null,
            null
    ),
    USDC(
            "USDC",
            "USD Coin",
            "USDC",
            6,
            CoinType.ETH,
            new BigDecimal("0.000001"),
            Set.of(Network.ETHEREUM),
            TokenType.ERC20,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            new BigDecimal("20")
    ),
    USDT(
            "USDT",
            "USD Tether",
            "USDT",
            6,
            CoinType.ETH,
            new BigDecimal("0.000001"),
            Set.of(Network.ETHEREUM),
            TokenType.ERC20,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            new BigDecimal("20")
    );

    final String code;
    final String name;
    final String iso;
    final Integer scale;
    final CoinType coinType;
    final BigDecimal minValue;
    final TokenType tokenType;
    final Set<Network> networks;
    final String smartContractAddress;
    final BigDecimal minAmountForGrabber;

    Currency(
            final @NonNull String code,
            final @NonNull String name,
            final @NonNull String iso,
            final @NonNull Integer scale,
            final @NonNull CoinType coinType,
            final @NonNull BigDecimal minValue,
            final @NonNull Set<Network> networks,
            final TokenType tokenType,
            final String smartContractAddress,
            final BigDecimal minAmountForGrabber
    ) {
        this.code = code;
        this.name = name;
        this.iso = iso;
        this.scale = scale;
        this.coinType = coinType;
        this.minValue = minValue.setScale(scale, RoundingMode.DOWN);
        this.networks = networks;
        this.tokenType = tokenType;

        if (smartContractAddress != null) {
            this.smartContractAddress = smartContractAddress.replace(" ", "");
        } else {
            this.smartContractAddress = null;
        }
        this.minAmountForGrabber = minAmountForGrabber;
    }

    public static Set<Currency> values(Network network, CoinType coinType) {
        if (network == null && coinType == null) {
            return Arrays.stream(Currency.values()).collect(Collectors.toSet());
        }
        if (network == null && coinType != null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getCoinType() == coinType)
                    .collect(Collectors.toSet());
        }
        if (network != null && coinType == null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getNetworks().contains(network))
                    .collect(Collectors.toSet());
        }
        if (network != null && coinType != null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getNetworks().contains(network) && item.getCoinType() == coinType)
                    .collect(Collectors.toSet());
        }
        return null; // this will never happen
    }

    public static Currency getCurrency(@NonNull String smartContractAddress, Network network, CoinType coinType) {
        smartContractAddress = smartContractAddress.replace(" ", "");
        Currency result = null;
        for (Currency currency : Currency.values(network, coinType)) {
            if (currency.getSmartContractAddress() != null) {
                if (currency.getSmartContractAddress().equalsIgnoreCase(smartContractAddress)) {
                    return currency;
                }
            }
        }
        return result;
    }

}
