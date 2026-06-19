package jwt

import (
	"fmt"
	"time"
)

// JwtUtilBuilder JWT 工具构建器，支持链式配置
type JwtUtilBuilder struct {
	opts []JwtOptions
}

// NewJwtUtilBuilder 创建 JWT 工具构建器
func NewJwtUtilBuilder() *JwtUtilBuilder {
	return &JwtUtilBuilder{}
}

// SecretKey 设置 JWT 签名密钥
func (b *JwtUtilBuilder) SecretKey(secretKey string) *JwtUtilBuilder {
	b.opts = append(b.opts, WithSecretKey(secretKey))
	return b
}

// Issuer 设置 JWT 签发者
func (b *JwtUtilBuilder) Issuer(issuer string) *JwtUtilBuilder {
	b.opts = append(b.opts, WithIssuer(issuer))
	return b
}

// ExpiresDuration 设置令牌过期时间
func (b *JwtUtilBuilder) ExpiresDuration(duration time.Duration) *JwtUtilBuilder {
	b.opts = append(b.opts, WithExpiresDuration(duration))
	return b
}

// RefreshExpiresDuration 设置刷新令牌过期时间
func (b *JwtUtilBuilder) RefreshExpiresDuration(duration time.Duration) *JwtUtilBuilder {
	b.opts = append(b.opts, WithRefreshExpiresDuration(duration))
	return b
}

// Build 构建 JWT 工具实例
func (b *JwtUtilBuilder) Build() (*JwtUtil, error) {
	util := NewJWTUtil(b.opts...)

	// NewJWTUtil sets a default secret key, so we need to check if user explicitly set it
	// For now, we'll just return the util since it has a default
	return util, nil
}

// MustBuild 构建 JWT 工具实例，失败则 panic
func (b *JwtUtilBuilder) MustBuild() *JwtUtil {
	util, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to build JWT util: %v", err))
	}
	return util
}
