package middleware

import (
	"encoding/base64"
	"sync"
	"testing"
)

func TestGenerateSessionKeysV3(t *testing.T) {
	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		t.Fatalf("GenerateSessionKeysV3() error = %v", err)
	}

	// Verify signing key
	signingBytes, err := base64.StdEncoding.DecodeString(signing)
	if err != nil {
		t.Errorf("signing key is not valid base64: %v", err)
	}
	if len(signingBytes) != 64 {
		t.Errorf("signing key length = %d, want 64", len(signingBytes))
	}

	// Verify encryption key
	encryptionBytes, err := base64.StdEncoding.DecodeString(encryption)
	if err != nil {
		t.Errorf("encryption key is not valid base64: %v", err)
	}
	if len(encryptionBytes) != 32 {
		t.Errorf("encryption key length = %d, want 32", len(encryptionBytes))
	}

	// Verify keys are different
	if signing == encryption {
		t.Error("signing and encryption keys should be different")
	}
}

func TestValidateSessionKeysV3(t *testing.T) {
	// Generate valid keys
	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		t.Fatalf("GenerateSessionKeysV3() error = %v", err)
	}

	tests := []struct {
		name       string
		signing    string
		encryption string
		wantErr    bool
	}{
		{
			name:       "valid keys",
			signing:    signing,
			encryption: encryption,
			wantErr:    false,
		},
		{
			name:       "empty signing key",
			signing:    "",
			encryption: encryption,
			wantErr:    true,
		},
		{
			name:       "empty encryption key",
			signing:    signing,
			encryption: "",
			wantErr:    true,
		},
		{
			name:       "invalid base64 signing key",
			signing:    "not-base64!@#$",
			encryption: encryption,
			wantErr:    true,
		},
		{
			name:       "wrong signing key length",
			signing:    base64.StdEncoding.EncodeToString([]byte("short")),
			encryption: encryption,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionKeysV3(tt.signing, tt.encryption)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSessionKeysV3() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInitSessionStoreV3(t *testing.T) {
	// Reset for testing
	ResetInitOnce()

	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		t.Fatalf("GenerateSessionKeysV3() error = %v", err)
	}

	err = InitSessionStoreV3(signing, encryption)
	if err != nil {
		t.Fatalf("InitSessionStoreV3() error = %v", err)
	}

	if StoreV3 == nil {
		t.Error("StoreV3 should be initialized")
	}

	options := GetStoreOptionsV3()
	if options == nil {
		t.Fatal("GetStoreOptionsV3() returned nil")
	}

	if !options.HttpOnly {
		t.Error("HttpOnly should be true")
	}
	if !options.Secure {
		t.Error("Secure should be true")
	}
}

func TestInitSessionStoreV3_Concurrent(t *testing.T) {
	// Reset for testing
	ResetInitOnce()

	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		t.Fatalf("GenerateSessionKeysV3() error = %v", err)
	}

	// Try to initialize concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := InitSessionStoreV3(signing, encryption)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// All goroutines should succeed (sync.Once ensures single init)
	for err := range errors {
		t.Errorf("concurrent InitSessionStoreV3() error = %v", err)
	}

	if StoreV3 == nil {
		t.Error("StoreV3 should be initialized after concurrent calls")
	}
}

func TestUpdateStoreOptionsV3(t *testing.T) {
	// Reset for testing
	ResetInitOnce()

	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		t.Fatalf("GenerateSessionKeysV3() error = %v", err)
	}

	err = InitSessionStoreV3(signing, encryption)
	if err != nil {
		t.Fatalf("InitSessionStoreV3() error = %v", err)
	}

	tests := []struct {
		name    string
		useTLS  bool
		wantErr bool
	}{
		{
			name:    "enable TLS",
			useTLS:  true,
			wantErr: false,
		},
		{
			name:    "disable TLS",
			useTLS:  false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdateStoreOptionsV3(tt.useTLS)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateStoreOptionsV3() error = %v, wantErr %v", err, tt.wantErr)
			}

			options := GetStoreOptionsV3()
			if options.Secure != tt.useTLS {
				t.Errorf("Secure flag = %v, want %v", options.Secure, tt.useTLS)
			}
		})
	}
}

func BenchmarkGenerateSessionKeysV3(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateSessionKeysV3()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateSessionKeysV3(b *testing.B) {
	signing, encryption, err := GenerateSessionKeysV3()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSessionKeysV3(signing, encryption)
	}
}
