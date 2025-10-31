package utilslib

import (
	"github.com/anthony-munozm/multipay-libs/redis"
	"github.com/anthony-munozm/multipay-libs/errormap"
	"log"
	"strings"
	"errors"
	"strconv"
	"math"
)

func GetDecimalsFromCurrency(currency string) (int, error, string) {
	currencies, err := redis.GetUniversalCacheTyped[[]map[string]interface{}](redis.Rdb, "currencies_catalog")
	if err != nil {
		return 0, errormap.GenerateErrorMessage("PAYMENT_INVALID_REQUEST", err.Error()), "PAYMENT_INVALID_REQUEST"
	}
	decimals := 2
    found := false
    for _, curr := range currencies {
        if code, ok := curr["code"].(string); ok && code == currency {
            log.Println("currencydecimals", curr["decimals"])
            var decimalsInt int
            switch v := curr["decimals"].(type) {
            case float64:
                decimalsInt = int(v)
            case int:
                decimalsInt = v
            case int32:
                decimalsInt = int(v)
            case int64:
                decimalsInt = int(v)
            default:
                return 0, errormap.GenerateErrorMessage("PAYMENT_INVALID_REQUEST", "decimals not found or invalid"), "PAYMENT_INVALID_REQUEST"
            }
            decimals = decimalsInt
            found = true
            break
        }
    }
    if !found {
        return 0, errormap.GenerateErrorMessage("PAYMENT_INVALID_REQUEST", "currency not found in catalog"), "PAYMENT_INVALID_REQUEST"
    }
    return decimals, nil, ""
}


func NormalizeAmount(amount string, decimals int) (string, error) {
	if strings.HasSuffix(amount, ".") {
		return "", errors.New("INVALID_AMOUNT_FORMAT")
	}

	if strings.Count(amount, ".") > 1 {
		return "", errors.New("INVALID_AMOUNT_FORMAT")
	}

	value, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return "", errors.New("INVALID_AMOUNT_FORMAT")
	}

	if value <= 0 {
		return "", errors.New("INVALID_AMOUNT")
	}

	integerValue := int64(value * math.Pow10(decimals))
	
	return strconv.FormatInt(integerValue, 10), nil
}

func NormalizeAmountReverse(amount string, decimals int) (string, error) {
	value, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return "", errors.New("INVALID_AMOUNT_FORMAT")
	}

	integerValue := float64(value / math.Pow10(decimals))
	
	return strconv.FormatFloat(integerValue, 'f', decimals, 64), nil
}