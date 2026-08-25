package iban

import (
	"errors"
	"regexp"
	"strings"
)

const TilopayEntityCode = "0369"

var crIBANPattern = regexp.MustCompile(`^CR\d{20}$`)

var ErrInvalidFormat = errors.New("invalid Costa Rican IBAN format")

// EntityCode extracts the entity code (positions 5-8, 1-indexed) from a valid
// Costa Rican IBAN (^CR\d{20}$). Returns ErrInvalidFormat when the format is invalid.
func EntityCode(iban string) (string, error) {
	iban = strings.ToUpper(strings.TrimSpace(iban))
	if !crIBANPattern.MatchString(iban) {
		return "", ErrInvalidFormat
	}
	return iban[4:8], nil
}

// IsLocalAccount reports whether the IBAN belongs to a Tilopay account.
func IsLocalAccount(iban string) (bool, error) {
	code, err := EntityCode(iban)
	if err != nil {
		return false, err
	}
	return code == TilopayEntityCode, nil
}
