package org.example.cryptotoolprojectdescription.enums;

import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.example.cryptotoolprojectdescription.enums.NetType.*;

import static lombok.AccessLevel.PRIVATE;

@Getter
@FieldDefaults(level = PRIVATE)
public enum Currency {

    AA1(
            "AA1",
            "AA1Token",
            "AA1",
            18,
            Network.ETHEREUM,
            new BigDecimal("0.000000000000000001"),
            Set.of(ETHEREUM),
            TokenType.ERC20,
            "0x9b8b16c5868a41eb9bb033dd271b3c68719f84a7",
            new BigDecimal("20")
    ),
    BTC(
            "BTC",
            "Bitcoin",
            "BTC",
            8,
            Network.BITCOIN,
            new BigDecimal("0.00000001"),
            Set.of(BITCOIN, BITCOIN_REGTEST, BITCOIN_REGTEST),
            null,
            null,
            null
    ),
    ETH(
            "ETH",
            "Ethereum",
            "ETH",
            18,
            Network.ETHEREUM,
            new BigDecimal("0.000000000000000001"),
            Set.of(ETHEREUM),
            null,
            null,
            null
    ),
    LTC(
            "LTC",
            "Litecoin",
            "LTC",
            8,
            Network.LITECOIN,
            new BigDecimal("0.00000001"),
            Set.of(LITECOIN, LITECOIN_TESTNET),
            null,
            null,
            null
    ),
    USDC(
            "USDC",
            "USD Coin",
            "USDC",
            6,
            Network.ETHEREUM,
            new BigDecimal("0.000001"),
            Set.of(ETHEREUM),
            TokenType.ERC20,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            new BigDecimal("20")
    ),
    USDT(
            "USDT",
            "USD Tether",
            "USDT",
            6,
            Network.ETHEREUM,
            new BigDecimal("0.000001"),
            Set.of(ETHEREUM),
            TokenType.ERC20,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            new BigDecimal("20")
    );

    final String code;
    final String name;
    final String iso;
    final Integer scale;
    final Network network;
    final BigDecimal minValue;
    final TokenType tokenType;
    final Set<NetType> netTypes;
    final String smartContractAddress;
    final BigDecimal minAmountForGrabber;

    Currency(
            final @NonNull String code,
            final @NonNull String name,
            final @NonNull String iso,
            final @NonNull Integer scale,
            final @NonNull Network network,
            final @NonNull BigDecimal minValue,
            final @NonNull Set<NetType> netTypes,
            final TokenType tokenType,
            final String smartContractAddress,
            final BigDecimal minAmountForGrabber
    ) {
        this.code = code;
        this.name = name;
        this.iso = iso;
        this.scale = scale;
        this.network = network;
        this.minValue = minValue.setScale(scale, RoundingMode.DOWN);
        this.netTypes = netTypes;
        this.tokenType = tokenType;
        this.smartContractAddress = smartContractAddress.replace(" ", "");
        this.minAmountForGrabber = minAmountForGrabber;
    }

    public static Set<Currency> values(NetType netType, Network network) {
        if (netType == null && network == null) {
            return Arrays.stream(Currency.values()).collect(Collectors.toSet());
        }
        if (netType == null && network != null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getNetwork() == network)
                    .collect(Collectors.toSet());
        }
        if (netType != null && network == null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getNetTypes().contains(netType))
                    .collect(Collectors.toSet());
        }
        if (netType != null && network != null) {
            return Arrays
                    .stream(Currency.values())
                    .filter(item -> item.getNetTypes().contains(netType) && item.getNetwork() == network)
                    .collect(Collectors.toSet());
        }
        return null; // this will never happen
    }

    public static Currency getCurrency(@NonNull String smartContractAddress, NetType netType, Network network) {
        smartContractAddress = smartContractAddress.replace(" ", "");
        Currency result = null;
        for (Currency currency : Currency.values(netType, network)) {
            if (currency.getSmartContractAddress() != null) {
                if (currency.getSmartContractAddress().equalsIgnoreCase(smartContractAddress)) {
                    return currency;
                }
            }
        }
        return result;
    }

}
