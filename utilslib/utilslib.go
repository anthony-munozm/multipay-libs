package utilslib

import (
	"github.com/anthony-munozm/multipay-libs/redis"
	"github.com/anthony-munozm/multipay-libs/errormap"
	"log"
	"strings"
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

func NormalizeAmount(amount string, decimals int) (int64, float64, error) {
	if strings.HasSuffix(amount, ".") {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", "amount ends with a dot")
	}

	if strings.Count(amount, ".") > 1 {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", "amount contains multiple dots")
	}

	// Validar que es un número válido
	value, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", err.Error())
	}

	if value <= 0 {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT", "amount is less than or equal to 0")
	}

	// Normalizar el string al formato con los decimales especificados
	normalizedString := strconv.FormatFloat(value, 'f', decimals, 64)
	normalizedFloat, err := strconv.ParseFloat(normalizedString, 64)
	if err != nil {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", err.Error())
	}
		
	// Eliminar el punto decimal del string normalizado
	integerString := strings.ReplaceAll(normalizedString, ".", "")
	integerValue, err := strconv.ParseInt(integerString, 10, 64)
	if err != nil {
		return 0, 0, errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", err.Error())
	}

	log.Println("NormalizeAmount value", value)
	log.Println("NormalizeAmount integerValue", integerString)
	log.Println("NormalizeAmount normalizedString", normalizedString)
	
	return integerValue, normalizedFloat, nil
}

func NormalizeAmountReverse(amount string, decimals int) (string, error) {
	value, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return "", errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", err.Error())
	}

	integerValue := float64(value / math.Pow10(decimals))
	
	return strconv.FormatFloat(integerValue, 'f', decimals, 64), nil
}

func NormalizeTruncateAmountReverseFromCurrency(amount string, currency string, decimalsTruncate int) (string, error) {
	value, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return "", errormap.GenerateErrorMessage("INVALID_AMOUNT_FORMAT", err.Error())
	}

	decimals, err, errorCode := GetDecimalsFromCurrency(currency)
	if err != nil {
		return "", errormap.GenerateErrorMessage(errorCode, err.Error())
	}

	integerValue := float64(value / math.Pow10(decimals))
	
	if decimalsTruncate > 0 {
		decimalsTruncate = 2
	}

	integerValue = math.Trunc(integerValue * math.Pow10(decimalsTruncate)) / math.Pow10(decimalsTruncate)

	return strconv.FormatFloat(integerValue, 'f', decimalsTruncate, 64), nil
}