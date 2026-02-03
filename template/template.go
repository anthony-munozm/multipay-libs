package template

import (
	"gopkg.in/yaml.v3"
	"os"
	"log"
	"reflect"
	"slices"
	"strconv"
	"regexp"
	"strings"
	"fmt"
)

type Rounding struct {
	SourceOfTruth string `yaml:"source_of_truth"`
	ModeDefault string `yaml:"mode_default"`
	EnforceScale bool `yaml:"enforce_scale"`
}

type Validation struct {
	ForbidZeroAmount bool `yaml:"forbid_zero_amount"`
	CurrencyRequired bool `yaml:"currency_required"`
	SymbolResolutionRequired bool `yaml:"symbol_resolution_required"`
	LedgerMustBalance bool `yaml:"ledger_must_balance"`
}

type Template struct {
	Template string `yaml:"template"`
	Version string `yaml:"version"`
	Description string `yaml:"description"`
	Data map[string]interface{} `yaml:"data"`
	Rounding Rounding `yaml:"rounding"`
	Validation Validation `yaml:"validation"`
}

func LoadTemplate(template_name string, version int) (Template, error) {
	file_path := "/multipay-core/services/transaction-core/internal/templates/" + template_name + ".v" + strconv.Itoa(version) + ".yaml"
	
	yamlFile, err := os.ReadFile(file_path)

	if err != nil {
		return Template{}, err
	}

	var template Template
	err = yaml.Unmarshal(yamlFile, &template)
	if err != nil {
		return Template{}, err
	}

	return template, nil
}

// convertEnumToStrings converts a YAML enum array from []interface{} to []string
func convertEnumToStrings(enum interface{}) []string {
	enumSlice, ok := enum.([]interface{})
	if !ok {
		return nil
	}
	enumStrings := make([]string, 0, len(enumSlice))
	for _, v := range enumSlice {
		if s, ok := v.(string); ok {
			enumStrings = append(enumStrings, s)
		}
	}
	return enumStrings
}

func ValidateList(item map[string]interface{}, tx []map[string]interface{}, exceptions []map[string]interface{}) []map[string]interface{} {
	for _, value := range tx {
		if item["properties"] != nil {
			propsMap, ok := item["properties"].(map[string]interface{})
			if !ok {
				continue
			}
			for key, prop := range propsMap {
				propMap, ok := prop.(map[string]interface{})
				if !ok {
					continue
				}
				if txValue, exists := value[key]; exists {
					if propMap["enum"] != nil {
						enumStrings := convertEnumToStrings(propMap["enum"])
						if strVal, ok := txValue.(string); ok && !slices.Contains(enumStrings, strVal) {
							exceptions = append(exceptions, map[string]interface{}{"message": key + " " + strVal + " not found in enum"})
						}
					}
				}
			}
		}
		exceptions = ValidateProperties(item, value, exceptions)
	}
	return exceptions
}

func ValidateProperties(properties map[string]interface{}, tx map[string]interface{}, exceptions []map[string]interface{}) []map[string]interface{} {

	if properties["properties"] != nil {
		propsMap, ok := properties["properties"].(map[string]interface{})
		if !ok {
			return exceptions
		}
		for key, prop := range propsMap {
			propMap, ok := prop.(map[string]interface{})
			if !ok {
				continue
			}
			if txValue, exists := tx[key]; exists {
				if reflect.TypeOf(txValue).Kind() == reflect.Map {
					if propMap["enum"] != nil {
						enumStrings := convertEnumToStrings(propMap["enum"])
						if strVal, ok := txValue.(string); ok && !slices.Contains(enumStrings, strVal) {
							exceptions = append(exceptions, map[string]interface{}{"message": key + " " + strVal + " not found in enum"})
						}
					}
					txValueMap, ok := txValue.(map[string]interface{})
					if ok {
						exceptions = ValidateProperties(propMap, txValueMap, exceptions)
					}
				} else if reflect.TypeOf(txValue).Kind() == reflect.Slice {
					itemSchema, ok := propMap["item"].(map[string]interface{})
					if !ok {
						continue
					}
					txValueList, ok := txValue.([]map[string]interface{})
					if !ok {
						continue
					}
					exceptions = ValidateList(itemSchema, txValueList, exceptions)
				}
			}
		}
	}

	if properties["required"] != nil {
		requiredSlice, ok := properties["required"].([]interface{})
		if !ok {
			return exceptions
		}
		for _, req := range requiredSlice {
			reqStr, ok := req.(string)
			if !ok {
				continue
			}
			if _, exists := tx[reqStr]; !exists {
				exceptions = append(exceptions, map[string]interface{}{"message": "Key " + reqStr + " not found in tx"})
			}
		}
	}

	return exceptions
}

func ValidateTemplate(tx map[string]interface{}, template_name string, version int) []map[string]interface{} {
	template, err := LoadTemplate(template_name, version)
	if err != nil {
		log.Println("Error loading template", err)
	}

	data := template

	exceptions := []map[string]interface{}{}

	exceptions = ValidateProperties(data.Data, tx, exceptions)

	for _, exception := range exceptions {
		log.Println("exception", exception)
	}
	
	return exceptions
}

func ReplaceTemplateVariables(value interface{}, tx map[string]interface{}) interface{} {
	if str, ok := value.(string); ok {
		re := regexp.MustCompile(`\{\{(\w+)\}\}`)
		
		return re.ReplaceAllStringFunc(str, func(match string) string {
			varName := strings.Trim(match, "{}")
			
			if txValue, exists := tx[varName]; exists {
				return fmt.Sprintf("%v", txValue)
			}
			
			log.Printf("Warning: Template variable %s not found in transaction data", varName)
			return match
		})
	}
	return value
}