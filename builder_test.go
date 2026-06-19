package jwt

import (
	"testing"
	"time"
)

func TestJwtUtilBuilder_Defaults(t *testing.T) {
	builder := NewJwtUtilBuilder()

	if builder == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestJwtUtilBuilder_ChainConfig(t *testing.T) {
	util, err := NewJwtUtilBuilder().
		SecretKey("test-secret-key").
		Issuer("test-issuer").
		ExpiresDuration(30 * time.Minute).
		RefreshExpiresDuration(2 * time.Hour).
		Build()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if util == nil {
		t.Fatal("expected non-nil util")
	}
}

func TestJwtUtilBuilder_MinimalConfig(t *testing.T) {
	util, err := NewJwtUtilBuilder().
		SecretKey("minimal-secret").
		Build()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if util == nil {
		t.Fatal("expected non-nil util")
	}
}

func TestJwtUtilBuilder_MustBuild(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("test-secret").
		MustBuild()

	if util == nil {
		t.Fatal("expected non-nil util")
	}
}

func TestJwtUtilBuilder_DefaultSecretKey(t *testing.T) {
	// NewJWTUtil sets a default secret key, so Build should succeed even without explicit SecretKey
	util, err := NewJwtUtilBuilder().Build()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if util == nil {
		t.Fatal("expected non-nil util")
	}

	// Should have default secret key
	if util.config.SecretKey == "" {
		t.Error("expected non-empty default secret key")
	}
}

func TestJwtUtilBuilder_AllOptions(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("full-config-secret").
		Issuer("my-app").
		ExpiresDuration(15 * time.Minute).
		RefreshExpiresDuration(1 * time.Hour).
		MustBuild()

	if util == nil {
		t.Fatal("expected non-nil util")
	}

	if util.config.SecretKey != "full-config-secret" {
		t.Errorf("expected SecretKey 'full-config-secret', got %s", util.config.SecretKey)
	}

	if util.config.Issuer != "my-app" {
		t.Errorf("expected Issuer 'my-app', got %s", util.config.Issuer)
	}

	if util.config.ExpiresDuration != 15*time.Minute {
		t.Errorf("expected ExpiresDuration 15m, got %v", util.config.ExpiresDuration)
	}

	if util.config.RefreshExpiresDuration != 1*time.Hour {
		t.Errorf("expected RefreshExpiresDuration 1h, got %v", util.config.RefreshExpiresDuration)
	}
}

func TestJwtUtilBuilder_TokenGeneration(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("token-test-secret").
		Issuer("test-app").
		ExpiresDuration(10 * time.Minute).
		MustBuild()

	// Test token generation
	accessToken, refreshToken, err := util.GenerateToken("test-user", "test-audience")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if accessToken == "" {
		t.Error("expected non-empty access token")
	}

	if refreshToken == "" {
		t.Error("expected non-empty refresh token")
	}

	// Test token validation
	valid, err := util.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if !valid {
		t.Error("expected token to be valid")
	}

	// Test subject extraction
	subject, err := util.GetSubject(accessToken)
	if err != nil {
		t.Fatalf("failed to get subject: %v", err)
	}

	if subject != "test-user" {
		t.Errorf("expected subject 'test-user', got %s", subject)
	}
}

func TestJwtUtilBuilder_TokenRefresh(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("refresh-test-secret").
		ExpiresDuration(5 * time.Minute).
		RefreshExpiresDuration(30 * time.Minute).
		MustBuild()

	// Generate initial token
	accessToken, refreshToken, err := util.GenerateToken("refresh-user")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Refresh token
	newAccessToken, newRefreshToken, err := util.RefreshToken(accessToken)
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("expected non-empty new access token")
	}

	if newRefreshToken == "" {
		t.Error("expected non-empty new refresh token")
	}

	// Verify new token is valid
	valid, err := util.ValidateToken(newAccessToken)
	if err != nil {
		t.Fatalf("failed to validate new token: %v", err)
	}

	if !valid {
		t.Error("expected new token to be valid")
	}

	// Original tokens should still be accessible
	_ = refreshToken
}

func TestJwtUtilBuilder_GetRemainingTime(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("time-test-secret").
		ExpiresDuration(10 * time.Minute).
		MustBuild()

	accessToken, _, err := util.GenerateToken("time-user")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	remaining, err := util.GetRemainingTime(accessToken)
	if err != nil {
		t.Fatalf("failed to get remaining time: %v", err)
	}

	if remaining <= 0 {
		t.Error("expected positive remaining time")
	}

	if remaining > 10*time.Minute {
		t.Errorf("expected remaining time <= 10m, got %v", remaining)
	}
}

func TestJwtUtilBuilder_GetClaims(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("claims-test-secret").
		Issuer("claims-issuer").
		MustBuild()

	accessToken, _, err := util.GenerateToken("claims-user", "claims-audience")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := util.GetClaims(accessToken)
	if err != nil {
		t.Fatalf("failed to get claims: %v", err)
	}

	if claims == nil {
		t.Fatal("expected non-nil claims")
	}

	if claims.Subject != "claims-user" {
		t.Errorf("expected subject 'claims-user', got %s", claims.Subject)
	}

	if claims.Issuer != "claims-issuer" {
		t.Errorf("expected issuer 'claims-issuer', got %s", claims.Issuer)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != "claims-audience" {
		t.Errorf("expected audience ['claims-audience'], got %v", claims.Audience)
	}
}

func TestJwtUtilBuilder_GetUserId(t *testing.T) {
	util := NewJwtUtilBuilder().
		SecretKey("userid-test-secret").
		MustBuild()

	accessToken, _, err := util.GenerateToken("userid-user")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	userId, err := util.GetUserId(accessToken)
	if err != nil {
		t.Fatalf("failed to get user ID: %v", err)
	}

	if userId == "" {
		t.Error("expected non-empty user ID")
	}
}
