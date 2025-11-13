package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("HERA V3 Session Key Generator")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	// Generate signing key (64 bytes)
	signingKey := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, signingKey); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to generate signing key: %v\n", err)
		os.Exit(1)
	}

	// Generate encryption key (32 bytes)
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to generate encryption key: %v\n", err)
		os.Exit(1)
	}

	// Encode to base64
	signingKeyB64 := base64.StdEncoding.EncodeToString(signingKey)
	encryptionKeyB64 := base64.StdEncoding.EncodeToString(encryptionKey)

	fmt.Println("✓ Generated secure session keys")
	fmt.Println()
	fmt.Println("Add these to your config.json:")
	fmt.Println()
	fmt.Println("{")
	fmt.Println("  \"admin_server\": { ... },")
	fmt.Println("  \"phish_server\": { ... },")
	fmt.Printf("  \"session_signing_key\": \"%s\",\n", signingKeyB64)
	fmt.Printf("  \"session_encryption_key\": \"%s\"\n", encryptionKeyB64)
	fmt.Println("}")
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("SECURITY WARNINGS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()
	fmt.Println("1. NEVER commit these keys to version control")
	fmt.Println("2. Store keys in environment variables or secure vault")
	fmt.Println("3. Use different keys for each environment (dev/staging/prod)")
	fmt.Println("4. Rotate keys quarterly")
	fmt.Println("5. If keys are compromised, regenerate immediately")
	fmt.Println()
	fmt.Println("Key Specifications:")
	fmt.Printf("  - Signing Key:    %d bytes (base64: %d chars)\n", len(signingKey), len(signingKeyB64))
	fmt.Printf("  - Encryption Key: %d bytes (base64: %d chars)\n", len(encryptionKey), len(encryptionKeyB64))
	fmt.Println()
	fmt.Println("To verify keys are loaded correctly:")
	fmt.Println("  1. Start Gophish")
	fmt.Println("  2. Check logs for: 'Session store V3 initialized'")
	fmt.Println("  3. Verify NO keys are logged (they should never appear in logs)")
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
}
