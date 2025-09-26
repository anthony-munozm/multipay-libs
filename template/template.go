package utils

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
	enumSlice := enum.([]interface{})
	enumStrings := make([]string, len(enumSlice))
	for i, v := range enumSlice {
		enumStrings[i] = v.(string)
	}
	return enumStrings
}

func ValidateList(item map[string]interface{}, tx []map[string]interface{}, exceptions []map[string]interface{}) []map[string]interface{} {
	for _, value := range tx {
		if item["properties"] != nil {
			for key, prop := range item["properties"].(map[string]interface{}) {
				if txValue, exists := value[key]; exists {
					if prop.(map[string]interface{})["enum"] != nil {
						enumStrings := convertEnumToStrings(prop.(map[string]interface{})["enum"])
						if !slices.Contains(enumStrings, txValue.(string)) {
							exceptions = append(exceptions, map[string]interface{}{"message": key + " " + txValue.(string) + " not found in enum"})
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
		for key, prop := range properties["properties"].(map[string]interface{}) {
			if txValue, exists := tx[key]; exists {
				if reflect.TypeOf(txValue).Kind() == reflect.Map {
					if prop.(map[string]interface{})["enum"] != nil {
						enumStrings := convertEnumToStrings(prop.(map[string]interface{})["enum"])
						if !slices.Contains(enumStrings, txValue.(string)) {
							exceptions = append(exceptions, map[string]interface{}{"message": key + " " + txValue.(string) + " not found in enum"})
						}
					}
					exceptions = ValidateProperties(prop.(map[string]interface{}), txValue.(map[string]interface{}), exceptions)
				}else if reflect.TypeOf(txValue).Kind() == reflect.Slice {
					exceptions = ValidateList(prop.(map[string]interface{})["item"].(map[string]interface{}), txValue.([]map[string]interface{}), exceptions)
				}
			}
		}
	}
	
	if properties["required"] != nil {
		for _, req := range properties["required"].([]interface{}) {
			if _, exists := tx[req.(string)]; !exists {
				exceptions = append(exceptions, map[string]interface{}{"message": "Key " + req.(string) + " not found in tx"})
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