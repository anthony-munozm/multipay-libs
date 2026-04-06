package validatemc

import (
	"log"
	"net/http"
	"fmt"
	"errors"
	"github.com/anthony-munozm/multipay-libs/bridge"
	"github.com/anthony-munozm/multipay-libs/logger"
	"github.com/labstack/echo/v4"
	"net/url"
	"encoding/json"
	"time"
	"regexp"
	"strconv"
	"net/mail"
)

type Identification struct {
	CountryCode    string `json:"country_code"`
	ExpirationDate string `json:"expiration_date"`
	Issuer         string `json:"issuer"`
}

type Contact struct {
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
}

type CustomerDTO struct {
	ID                   string                 `json:"id"`
	Type                 string                 `json:"type"`
	LegalName            string                 `json:"legal_name"`
	FirstName            string                 `json:"first_name"`
	MiddleName           string                 `json:"middle_name"`
	LastName             string                 `json:"last_name"`
	SecondLastName       string                 `json:"second_last_name"`
	Identification       Identification         `json:"identification"`
	Contact              Contact                `json:"contact"`
	TenantID             string                 `json:"tenant_id"`
	PartnerID            string                 `json:"partner_id"`
	Segment              string                 `json:"segment"`
	Status               string                 `json:"status"`
	KYCLevel             string                 `json:"kyc_level"`
	IdentificationType   string                 `json:"identification_type"`
	IdentificationNumber string                 `json:"identification_number"`
	Metadata             map[string]interface{} `json:"metadata"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type SchemaProperty struct {
	Type      string `json:"type"`
	Format    string `json:"format,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	MaxLength int    `json:"maxLength,omitempty"`
	MinLength int    `json:"minLength,omitempty"`
}

type Schema struct {
	Type       string                    `json:"type"`
	Properties map[string]SchemaProperty `json:"properties"`
	Required   []string                  `json:"required"`
}

func GetIdentificationSchemaService(c echo.Context, issuer, countryCode string) (interface{}, error) {
	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService request: %+v", c.Request()), nil)
	headers := make(http.Header)
	if c != nil && c.Request() != nil {
		headers = c.Request().Header
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService headers: %+v", headers), nil)

	path := fmt.Sprintf("/assignments/metadata?issuer=%s&country_code=%s",
		url.QueryEscape(issuer),
		url.QueryEscape(countryCode),
	)

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService path: %s", path), nil)

	resp := bridge.MicroserviceC.CallIssuerCore("GET", path, nil, headers)
	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService resp: %+v", resp), nil)
	if c != nil {
		logger.LogInfo("GetIdentificationSchema Raw response from issuer-core: ", c.Request())
	}
	log.Printf("Raw response from issuer-core: %+v\n", resp)

	respMap, ok := resp.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("respuesta inválida del issuer-core: formato inesperado")
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService respMap: %+v", respMap), nil)

	if success, _ := respMap["success"].(bool); !success {
		var errorMsg string
		if msg := respMap["message"]; msg != nil {
			errorMsg = fmt.Sprintf("%v", msg)
		} else {
			errorMsg = "error desconocido"
		}
		if errorsField := respMap["errors"]; errorsField != nil {
			errorMsg += fmt.Sprintf(" - Detalles: %v", errorsField)
		}
		return nil, fmt.Errorf("issuer-core devolvió error: %s", errorMsg)
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService success"), nil)

	// Type assertion de data
	responseIface, ok := respMap["data"]
	if !ok {
		return nil, fmt.Errorf("formato inesperado: no hay 'data' en issuer-core")
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService responseIface: %+v", responseIface), nil)

	responseObj, ok := responseIface.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("formato inesperado: 'data' no es un objeto")
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService responseObj: %+v", responseObj), nil)

	schema, ok := responseObj["identification_schema"]
	if !ok {
		var availableKeys []string
		for key := range responseObj {
			availableKeys = append(availableKeys, key)
		}
		return nil, fmt.Errorf("no se encontró identification_schema en metadata. Claves disponibles: %v", availableKeys)
	}

	logger.LogInfo(fmt.Sprintf("GetIdentificationSchemaService schema: %+v", schema), nil)

	return schema, nil
}

func GetContactSchemaService(c echo.Context, issuer, countryCode string) (interface{}, error) {
	logger.LogInfo(fmt.Sprintf("GetContactSchemaService request: %+v", c.Request()), nil)
	headers := make(http.Header)
	if c != nil && c.Request() != nil {
		headers = c.Request().Header
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService headers: %+v", headers), nil)

	path := fmt.Sprintf("/assignments/metadata?issuer=%s&country_code=%s",
		url.QueryEscape(issuer),
		url.QueryEscape(countryCode),
	)

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService path: %s", path), nil)

	resp := bridge.MicroserviceC.CallIssuerCore("GET", path, nil, headers)
	logger.LogInfo(fmt.Sprintf("GetContactSchemaService resp: %+v", resp), nil)
	if c != nil {
		logger.LogInfo("GetContactSchema Raw data from issuer-core: ", c.Request())
	}
	log.Printf("Raw data from issuer-core: %+v\n", resp)

	respMap, ok := resp.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("respuesta inválida del issuer-core: formato inesperado")
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService respMap: %+v", respMap), nil)

	if success, _ := respMap["success"].(bool); !success {
		var errorMsg string
		if msg := respMap["message"]; msg != nil {
			errorMsg = fmt.Sprintf("%v", msg)
		} else {
			errorMsg = "error desconocido"
		}
		if errorsField := respMap["errors"]; errorsField != nil {
			errorMsg += fmt.Sprintf(" - Detalles: %v", errorsField)
		}
		return nil, fmt.Errorf("issuer-core devolvió error: %s", errorMsg)
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService success"), nil)

	// Type assertion de data
	responseIface, ok := respMap["data"]
	if !ok {
		return nil, fmt.Errorf("formato inesperado: no hay 'data' en issuer-core")
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService responseIface: %+v", responseIface), nil)

	responseObj, ok := responseIface.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("formato inesperado: 'data' no es un objeto")
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService responseObj: %+v", responseObj), nil)

	schema, ok := responseObj["contact_schema"]
	if !ok {
		var availableKeys []string
		for key := range responseObj {
			availableKeys = append(availableKeys, key)
		}
		return nil, fmt.Errorf("no se encontró contact_schema en metadata. Claves disponibles: %v", availableKeys)
	}

	logger.LogInfo(fmt.Sprintf("GetContactSchemaService schema: %+v", schema), nil)

	return schema, nil
}

func StructToMapService(s interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// validateCustomerSchemas valida los campos identification y contact contra sus schemas
func ValidateCustomerSchemasService(c echo.Context, identification, contact map[string]interface{}, identSchemaResp interface{}, contactSchemaResp interface{}) error {
	// Extraer issuer y country_code del metadata

	// --- IDENTIFICATION ---
	if identification != nil && len(identification) > 0 {

		identSchema, err := ParseSchemaService(identSchemaResp)
		if err != nil {
			// Loguear respuesta cruda para debug
			logger.LogInfo(fmt.Sprintf("Respuesta inválida de issuer-core (identification): %+v", identSchemaResp), c.Request())

			return fmt.Errorf("respuesta inválida del issuer-core al parsear identification schema: %w", err)
		}

		if err := ValidateAgainstSchemaService(identification, identSchema, "identification"); err != nil {
			return fmt.Errorf("identification inválido contra schema: %w", err)
		}
	}

	// --- CONTACT ---
	if contact != nil && len(contact) > 0 {

		contactSchema, err := ParseSchemaService(contactSchemaResp)
		if err != nil {
			// Loguear respuesta cruda para debug
			logger.LogInfo(fmt.Sprintf("Respuesta inválida de issuer-core (contact): %+v", contactSchemaResp), c.Request())

			return fmt.Errorf("respuesta inválida del issuer-core al parsear contact schema: %w", err)
		}

		if err := ValidateAgainstSchemaService(contact, contactSchema, "contact"); err != nil {
			return fmt.Errorf("contact inválido contra schema: %w", err)
		}
	}

	return nil
}

func ParseSchemaService(schemaInterface interface{}) (Schema, error) {
	var schema Schema

	schemaBytes, err := json.Marshal(schemaInterface)
	if err != nil {
		return schema, fmt.Errorf("error al convertir schema a JSON: %w", err)
	}

	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		return schema, fmt.Errorf("error al parsear schema: %w", err)
	}

	return schema, nil
}

func ValidateAgainstSchemaService(data map[string]interface{}, schema Schema, schemaType string) error {
	// Validar campos requeridos
	for _, requiredField := range schema.Required {
		if _, exists := data[requiredField]; !exists {
			return fmt.Errorf("el campo %s es obligatorio en %s", requiredField, schemaType)
		}
	}

	// Validar cada campo según sus propiedades
	for fieldName, fieldValue := range data {
		if property, exists := schema.Properties[fieldName]; exists {
			if err := ValidateSchemaFieldService(fieldName, fieldValue, property); err != nil {
				return fmt.Errorf("validación de %s falló: %w", schemaType, err)
			}
		}
	}

	return nil
}

func ValidateSchemaFieldService(fieldName string, fieldValue interface{}, property SchemaProperty) error {
	if fieldValue == nil {
		return nil // Los campos opcionales pueden ser nil
	}

	valueStr := fmt.Sprintf("%v", fieldValue)

	switch property.Type {
	case "string":
		if property.Format == "email" {
			if _, err := mail.ParseAddress(valueStr); err != nil {
				return fmt.Errorf("el campo %s debe ser un email válido", fieldName)
			}
		}
		if property.Format == "date" {
			if _, err := time.Parse("2006-01-02", valueStr); err != nil {
				return fmt.Errorf("el campo %s debe tener formato de fecha YYYY-MM-DD", fieldName)
			}
		}
		if property.Pattern != "" {
			matched, err := regexp.MatchString(property.Pattern, valueStr)
			if err != nil {
				return fmt.Errorf("error en el patrón de validación para %s", fieldName)
			}
			if !matched {
				return fmt.Errorf("el campo %s no cumple con el patrón requerido", fieldName)
			}
		}
		if property.MaxLength > 0 && len(valueStr) > property.MaxLength {
			return fmt.Errorf("el campo %s excede la longitud máxima de %d caracteres", fieldName, property.MaxLength)
		}
		if property.MinLength > 0 && len(valueStr) < property.MinLength {
			return fmt.Errorf("el campo %s debe tener al menos %d caracteres", fieldName, property.MinLength)
		}
	case "number", "integer":
		if _, err := strconv.ParseFloat(valueStr, 64); err != nil {
			return fmt.Errorf("el campo %s debe ser un número válido", fieldName)
		}
	}

	return nil
}

func ValidateMetadataService(c echo.Context, req CustomerDTO) (error) {
	logger.LogInfo(fmt.Sprintf("ValidateMetadataService request: %+v", req), nil)
	countryCode, ok := req.Metadata["country_code"].(string)
	if !ok || countryCode == "" {
		return fmt.Errorf("el campo country_code es requerido en metadata para validación de schemas")
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService countryCode: %s", countryCode), nil)

	if countryCode == "CR" && req.Type == "" {
		return errors.New("el campo type es obligatorio para clientes en Costa Rica")
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService issuer"), nil)

	issuer, ok := req.Metadata["issuer"].(string)
	if !ok || issuer == "" {
		return fmt.Errorf("el campo issuer es requerido en metadata para validación de schemas")
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService issuer: %s", issuer), nil)

	identSchemaResp, err := GetIdentificationSchemaService(c, issuer, countryCode)
	if err != nil {
		return fmt.Errorf("error obteniendo identification schema desde issuer-core: %w", err)
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService identSchemaResp: %+v", identSchemaResp), nil)

	contactSchemaResp, err := GetContactSchemaService(c, issuer, countryCode)
	if err != nil {
		return fmt.Errorf("error obteniendo contact schema desde issuer-core: %w", err)
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService contactSchemaResp: %+v", contactSchemaResp), nil)

	identMap, err := StructToMapService(req.Identification)
	if err != nil {
		return fmt.Errorf("error convirtiendo identification: %w", err)
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService identMap: %+v", identMap), nil)

	contactMap, err := StructToMapService(req.Contact)
	if err != nil {
		return fmt.Errorf("error convirtiendo contact: %w", err)
	}

	logger.LogInfo(fmt.Sprintf("ValidateMetadataService contactMap: %+v", contactMap), nil)

	if err := ValidateCustomerSchemasService(c, identMap, contactMap, identSchemaResp, contactSchemaResp); err != nil {
		return fmt.Errorf("validación de schemas falló: %w", err)
	}

	logger.LogInfo("ValidateMetadataService validation successful", nil)

	return nil
}