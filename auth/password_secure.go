package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Enhanced password policy constants
const (
	MinPasswordEntropy  = 40.0 // bits
	PasswordHistorySize = 5    // Remember last 5 passwords
)

// Additional error types
var (
	ErrPasswordTooWeak = errors.New("password does not meet security requirements")
)

// CheckPasswordPolicyEnhanced performs enhanced password policy validation
func CheckPasswordPolicyEnhanced(password string) error {
	switch {
	case password == "":
		return ErrEmptyPassword
	case len(password) < MinPasswordLength:
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	case len(password) > MaxPasswordLength:
		return fmt.Errorf("password must be less than %d characters", MaxPasswordLength)
	}

	// Note: Full password strength checking would require models.CheckPasswordStrength
	// which is in the models package. For auth package, we keep basic checks here
	// and rely on the caller to do full strength checking.

	return nil
}

// ValidatePasswordChangeEnhanced includes additional security checks
func ValidatePasswordChangeEnhanced(currentHash, newPassword, confirmPassword string) (string, error) {
	// Basic policy check
	if err := CheckPasswordPolicyEnhanced(newPassword); err != nil {
		return "", err
	}

	// Check that new passwords match
	if newPassword != confirmPassword {
		return "", ErrPasswordMismatch
	}

	// Make sure that the new password isn't the same as the old one
	err := ValidatePassword(newPassword, currentHash)
	if err == nil {
		return "", ErrReusedPassword
	}

	// Generate the new hash
	newHash, err := GeneratePasswordHash(newPassword)
	if err != nil {
		return "", err
	}

	return newHash, nil
}

// GeneratePasswordHashWithCost allows specifying bcrypt cost
func GeneratePasswordHashWithCost(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}

	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPasswordHashCost returns the cost factor used for a hash
func CheckPasswordHashCost(hash string) (int, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return 0, err
	}
	return cost, nil
}
