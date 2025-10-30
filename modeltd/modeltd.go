package modeltd

import (
  "net/http"
  "fmt"
  "github.com/anthony-munozm/multipay-libs/bridge"
)

func GetDataFromCallBridge(data interface{}, originalValue interface{}) interface{} {
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

func ModelToDict(fieldName string, idValue string, originalValue interface{}, headers http.Header) interface{} {
	switch fieldName {
	case "issuer_assignment_id":
		return GetDataFromCallBridge(bridge.MicroserviceC.CallIssuerCore("GET", fmt.Sprintf("/assignments/%s", idValue), nil, headers), originalValue)
	case "tenant_id":
		return GetDataFromCallBridge(bridge.MicroserviceC.CallAdminCore("GET", fmt.Sprintf("/tenants/%s", idValue), nil, headers), originalValue)
	case "to_account_id", "from_account_id":
		return GetDataFromCallBridge(bridge.MicroserviceC.CallAccountingCore("GET", fmt.Sprintf("/%s", idValue), nil, headers), originalValue)
	case "payment_method_id":
		return GetDataFromCallBridge(bridge.MicroserviceC.CallTransactionCore("GET", fmt.Sprintf("/payment-methods/%s", idValue), nil, headers), originalValue)
	default:
		return originalValue
	}
}

func CheckModelsToDict(data interface{}, headers http.Header) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		maskedMap := make(map[string]interface{})
		for key, value := range v {
			if len(key) > 3 && key[len(key)-3:] == "_id" {
				idStr, ok := value.(string)
				if !ok {
					maskedMap[key] = CheckModelsToDict(value, headers)
					continue
				}
				
				maskedMap[key] = ModelToDict(key, idStr, value, headers)
			} else {
				maskedMap[key] = CheckModelsToDict(value, headers)
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