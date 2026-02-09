package modeltd

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/anthony-munozm/multipay-libs/bridge"
	"github.com/anthony-munozm/multipay-libs/logger"
)

// DictResult holds both the id value and the resolved object for _id fields.
// When Resolved is non-nil, the caller should set both key and key without "_id".
type DictResult struct {
	IDValue  interface{} // value for the _id key (e.g. original id)
	Resolved interface{} // value for key without _id; nil if call failed or invalid response
}

func GetDataFromCallBridge(data interface{}, originalValue interface{}) interface{} {
	logger.LogInfo(fmt.Sprintf("GetDataFromCallBridge - data: %v", data), nil)
	logger.LogInfo(fmt.Sprintf("GetDataFromCallBridge - originalValue: %v", originalValue), nil)
	respMap, ok := data.(map[string]interface{})
	if !ok {
		return originalValue
	}
	responseIface, ok := respMap["data"]
	if !ok {
		return originalValue
	}
	responseObj, ok := responseIface.(map[string]interface{})
	if !ok {
		return originalValue
	}

	return responseObj
}

// nilUUID is the zero value UUID; account IDs with this value should not be resolved via API.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// allowedIDFields is the list of field names that may be resolved via ModelToDict.
// Only keys in this list are passed to ModelToDict; other *_id fields are left as-is.
var allowedIDFields = []string{
	"issuer_assignment_id",
	"tenant_id",
	"to_account_id",
	"from_account_id",
	"payment_method_id",
}

func isAllowedIDField(fieldName string) bool {
	return slices.Contains(allowedIDFields, fieldName)
}

// shouldResolveID returns false when idValue is empty/whitespace or when it is the nil UUID for account fields.
func shouldResolveID(idValue string, fieldName string) bool {
	idValue = strings.TrimSpace(idValue)
	if idValue == "" {
		return false
	}
	if fieldName == "to_account_id" || fieldName == "from_account_id" {
		if idValue == nilUUID {
			return false
		}
	}
	return true
}

// isValidBridgeResponse returns true when the bridge response is a successful map with "data" and no "error".
func isValidBridgeResponse(response interface{}) bool {
	respMap, ok := response.(map[string]interface{})
	if !ok {
		return false
	}
	if _, hasError := respMap["error"]; hasError {
		return false
	}
	_, hasData := respMap["data"]
	return hasData
}

func ModelToDict(fieldName string, idValue string, originalValue interface{}, headers http.Header) interface{} {
	if !shouldResolveID(idValue, fieldName) {
		return DictResult{IDValue: originalValue, Resolved: nil}
	}
	switch fieldName {
	case "issuer_assignment_id":
		logger.LogInfo(fmt.Sprintf("ModelToDict - issuer_assignment_id: %s", idValue), nil)
		response := bridge.MicroserviceC.CallIssuerCore("GET", fmt.Sprintf("/assignments/%s", idValue), nil, headers)
		if !isValidBridgeResponse(response) {
			return DictResult{IDValue: originalValue, Resolved: nil}
		}
		resolved := GetDataFromCallBridge(response, originalValue)
		return DictResult{IDValue: originalValue, Resolved: resolved}
	case "tenant_id":
		logger.LogInfo(fmt.Sprintf("ModelToDict - tenant_id: %s", idValue), nil)
		response := bridge.MicroserviceC.CallAdminCore("GET", fmt.Sprintf("/tenants/%s", idValue), nil, headers)
		if !isValidBridgeResponse(response) {
			return DictResult{IDValue: originalValue, Resolved: nil}
		}
		resolved := GetDataFromCallBridge(response, originalValue)
		return DictResult{IDValue: originalValue, Resolved: resolved}
	case "to_account_id", "from_account_id":
		logger.LogInfo(fmt.Sprintf("ModelToDict - to_account_id or from_account_id: %s", idValue), nil)
		response := bridge.MicroserviceC.CallAccountingCore("GET", fmt.Sprintf("/%s", idValue), nil, headers)
		if !isValidBridgeResponse(response) {
			return DictResult{IDValue: originalValue, Resolved: nil}
		}
		resolved := GetDataFromCallBridge(response, originalValue)
		return DictResult{IDValue: originalValue, Resolved: resolved}
	case "payment_method_id":
		logger.LogInfo(fmt.Sprintf("ModelToDict - payment_method_id: %s", idValue), nil)
		response := bridge.MicroserviceC.CallTransactionCore("GET", fmt.Sprintf("/payment-methods/%s", idValue), nil, headers)
		if !isValidBridgeResponse(response) {
			return DictResult{IDValue: originalValue, Resolved: nil}
		}
		resolved := GetDataFromCallBridge(response, originalValue)
		return DictResult{IDValue: originalValue, Resolved: resolved}
	default:
		return originalValue
	}
}

func CheckModelsToDict(data interface{}, headers http.Header) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		maskedMap := make(map[string]interface{})
		for key, value := range v {
			if len(key) > 3 && key[len(key)-3:] == "_id" && isAllowedIDField(key) {
				idStr, ok := value.(string)
				if !ok {
					maskedMap[key] = CheckModelsToDict(value, headers)
					continue
				}

				logger.LogInfo(fmt.Sprintf("ModelToDict - key: %s idStr: %s", key, idStr), nil)

				result := ModelToDict(key, idStr, value, headers)
				if dr, ok := result.(DictResult); ok {
					maskedMap[key] = dr.IDValue
					if dr.Resolved != nil {
						maskedMap[strings.TrimSuffix(key, "_id")] = dr.Resolved
					}
				} else {
					maskedMap[key] = result
				}
			} else {
				maskedMap[key] = value
			}
		}
		return maskedMap
	case []interface{}:
		maskedSlice := make([]interface{}, len(v))
		for i, value := range v {
			maskedSlice[i] = CheckModelsToDict(value, headers)
		}
		return maskedSlice
	default:
		return v
	}
}