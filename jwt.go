// Package jwt 提供 JWT（JSON Web Token）令牌的生成、解析和验证功能。
//
// 基于 golang-jwt/jwt/v5 库实现，支持 HMAC-SHA256 签名算法。
// 提供令牌生成、解析、刷新和 Bearer Token 提取等功能。
//
// 核心组件：
//   - JwtUtil: JWT 工具类，封装令牌操作
//   - jwtConfig: JWT 配置，包含密钥、签发者、过期时间等
//   - JwtOptions: 函数式配置选项
package jwt

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config JWT 配置
type jwtConfig struct {
	SecretKey              string        `json:"secret_key"`               // 密钥
	Issuer                 string        `json:"issuer"`                   // 签发者
	ExpiresDuration        time.Duration `json:"expires_duration"`         // 过期时间
	RefreshExpiresDuration time.Duration `json:"refresh_expires_duration"` // 刷新过期时间
}

// JwtUtil JWT 工具类，封装令牌的生成、解析和验证操作
type JwtUtil struct {
	config *jwtConfig // JWT 配置
}

// JwtOptions JWT 配置选项函数
type JwtOptions func(*jwtConfig)

// WithSecretKey 设置 JWT 签名密钥
func WithSecretKey(secretKey string) JwtOptions {
	return func(config *jwtConfig) {
		config.SecretKey = secretKey
	}
}

// WithIssuer 设置 JWT 签发者
func WithIssuer(issuer string) JwtOptions {
	return func(config *jwtConfig) {
		config.Issuer = issuer
	}
}

// WithExpiresDuration 设置令牌过期时间
func WithExpiresDuration(duration time.Duration) JwtOptions {
	return func(config *jwtConfig) {
		config.ExpiresDuration = duration
	}
}

// WithRefreshExpiresDuration 设置刷新令牌过期时间
func WithRefreshExpiresDuration(duration time.Duration) JwtOptions {
	return func(config *jwtConfig) {
		config.RefreshExpiresDuration = duration
	}
}

// NewJWTUtil 创建新的 JWT 工具实例
func NewJWTUtil(jwtOptions ...JwtOptions) *JwtUtil {
	config := &jwtConfig{
		SecretKey:              "go-bootJwtSecret", // 默认密钥
		Issuer:                 "go-boot",          // 默认签发者
		ExpiresDuration:        time.Minute * 10,   // 默认过期时间
		RefreshExpiresDuration: time.Hour * 1,      // 默认刷新过期时间
	}

	for _, opt := range jwtOptions {
		opt(config)
	}

	// 过期时间不能超过 1 小时
	if config.ExpiresDuration > time.Hour*1 {
		config.ExpiresDuration = time.Hour * 1
	} else if config.ExpiresDuration <= 0 {
		config.ExpiresDuration = time.Minute * 10
	}

	// 刷新过期时间必须大于过期时间
	if config.RefreshExpiresDuration < config.ExpiresDuration {
		config.RefreshExpiresDuration = config.ExpiresDuration + time.Minute*10
	}

	return &JwtUtil{config: config}
}

// GenerateToken 生成访问令牌和刷新令牌
//
// 参数：
//   - username: 用户名，将作为 Token 的 Subject
//   - aud: 可选的受众声明
//
// 返回值：
//   - tokenString: 访问令牌
//   - refreshTokenString: 刷新令牌
//   - error: 生成错误
func (j *JwtUtil) GenerateToken(username string, aud ...string) (string, string, error) {
	if j.config.SecretKey == "" {
		return "", "", errors.New("secret key is empty")
	}
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.config.ExpiresDuration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Audience:  aud,
		Subject:   username,
		Issuer:    j.config.Issuer,
	}

	jsonData, err := json.Marshal(claims)
	if err != nil {
		return "", "", err
	}
	id, err := generateUniqueID(jsonData)
	if err != nil {
		return "", "", err
	}
	claims.ID = id
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.config.SecretKey))
	if err != nil {
		return "", "", err
	}

	refreshClaims := claims
	refreshClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(j.config.RefreshExpiresDuration))
	jsonData2, err := json.Marshal(refreshClaims)
	if err != nil {
		return "", "", err
	}
	id2, err := generateUniqueID(jsonData2)
	if err != nil {
		return "", "", err
	}
	refreshClaims.ID = id2

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(j.config.SecretKey))
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}

// ParseToken 解析并验证令牌，返回注册声明信息
func (j *JwtUtil) ParseToken(tokenString string) (*jwt.RegisteredClaims, error) {
	if j.config.SecretKey == "" {
		return nil, errors.New("secret key is empty")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.config.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidateToken 验证令牌是否有效且未过期
func (j *JwtUtil) ValidateToken(tokenString string) (bool, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return false, err
	}

	// 检查是否过期
	if time.Now().After(claims.ExpiresAt.Time) {
		return false, errors.New("token is expired")
	}

	return true, nil
}

// RefreshToken 使用现有令牌刷新生成新的访问令牌和刷新令牌
func (j *JwtUtil) RefreshToken(tokenString string) (string, string, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return "", "", err
	}

	// 生成新的 Token
	newToken, newRefreshToken, err := j.GenerateToken(claims.Subject, claims.Audience...)
	if err != nil {
		return "", "", err
	}

	return newToken, newRefreshToken, nil
}

// GetClaims 获取令牌中的注册声明信息
func (j *JwtUtil) GetClaims(tokenString string) (*jwt.RegisteredClaims, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// GetSubject 获取令牌中的用户名（Subject 声明）
func (j *JwtUtil) GetSubject(tokenString string) (string, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// GetUserId 获取令牌中的唯一标识（ID 声明）
func (j *JwtUtil) GetUserId(tokenString string) (string, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.ID, nil
}

// GetRemainingTime 获取令牌的剩余有效时间
func (j *JwtUtil) GetRemainingTime(tokenString string) (time.Duration, error) {
	claims, err := j.ParseToken(tokenString)
	if err != nil {
		return 0, err
	}
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 0 {
		return 0, errors.New("token is expired")
	}
	return remaining, nil
}

// MD5 计算字节切片的 MD5 哈希值，返回十六进制字符串
func MD5(data []byte) string {
	hash := md5.Sum(data) // 返回 [16]byte 数组
	return hex.EncodeToString(hash[:])
}

// generateUniqueID 生成唯一 ID，结合数据和随机字节确保唯一性
func generateUniqueID(data []byte) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	combined := append(data, randBytes...)
	return MD5(combined), nil
}

// ExtractBearerToken 从 Authorization 头中提取 Bearer token
func ExtractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(authHeader) >= len(prefix) && strings.HasPrefix(authHeader, prefix) {
		return authHeader[len(prefix):]
	}
	return ""
}
