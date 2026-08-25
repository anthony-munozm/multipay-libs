package iban

import (
	"errors"
	"testing"
)

func TestEntityCode_Tilopay(t *testing.T) {
	code, err := EntityCode("CR12036900101019858991")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != TilopayEntityCode {
		t.Fatalf("expected entity code %q, got %q", TilopayEntityCode, code)
	}
}

func TestEntityCode_OtherEntity(t *testing.T) {
	code, err := EntityCode("CR12015200101019858991")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code == TilopayEntityCode {
		t.Fatalf("expected a non-Tilopay entity code, got %q", code)
	}
	if code != "0152" {
		t.Fatalf("expected entity code 0152, got %q", code)
	}
}

func TestEntityCode_InvalidIBAN(t *testing.T) {
	_, err := EntityCode("CR123")
	if !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestIsLocalAccount(t *testing.T) {
	tests := []struct {
		name    string
		iban    string
		want    bool
		wantErr bool
	}{
		{
			name: "tilopay account",
			iban: "CR12036900101019858991",
			want: true,
		},
		{
			name: "other entity",
			iban: "CR12015200101019858991",
			want: false,
		},
		{
			name:    "invalid iban",
			iban:    "INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsLocalAccount(tt.iban)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("IsLocalAccount(%q) = %v, want %v", tt.iban, got, tt.want)
			}
		})
	}
}
