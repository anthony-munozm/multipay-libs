package errormap

import (
	"runtime"
	"os"
	"github.com/anthony-munozm/multipay-libs/redis"
	"fmt"
)

func GenerateErrorMessage(code string, detalle string) map[string]interface{} {
	functionName := "unknown"
	line := 0
	microserviceName := "unknown"
	
	pc, _, lineNum, ok := runtime.Caller(1)
	if ok {
		line = lineNum
		fn := runtime.FuncForPC(pc)
		if fn != nil {
			functionName = fn.Name()
		}
	}

	if os.Getenv("MICROSERVICE_NAME") != "" {
		microserviceName = os.Getenv("MICROSERVICE_NAME")
	}

	returnMap := map[string]interface{}{
		"http_status": 404,
		"message": fmt.Errorf("[%s] Error en %s() línea %d → %s: %s -> detalle: %s", microserviceName, functionName, line, "GLOBAL_CATALOG_ERROR_NOT_FOUND", "Error Code not found, please check the global catalog errors", detalle),
	}
	globalCatalogErrors, err := redis.GetUniversalCacheTyped[map[string]interface{}](redis.Rdb, "global_catalog_errors")
	if err != nil {
		return returnMap
	}

	if globalCatalogError, ok := globalCatalogErrors[code]; ok && globalCatalogError != "" {
		if respMap, ok := globalCatalogError.(map[string]interface{}); ok && respMap != nil {
			if msg, ok := respMap["message"].(string); ok && msg != "" {
				if httpStatusCode, ok := respMap["http_status_code"].(int); ok {
					returnMap["http_status"] = httpStatusCode
				}
				returnMap["message"] = fmt.Errorf("[%s] Error en %s() línea %d → %s: %s -> detalle: %s", microserviceName, functionName, line, code, respMap["message"].(string), detalle)
				return returnMap
			}
		}
	}

	return returnMap

}