// Package jwt 提供 JWT 认证的自动配置。
//
// 当 jwt.enabled=true 时自动启用，从 Environment 中读取 jwt.secret-key、jwt.issuer、jwt.expires-duration 等配置项，
// 创建并注册 JWT 工具 Bean 到 IoC 容器中（Bean ID: jwtUtil）。
package jwt

import (
	"strings"
	"time"

	jwtcore "github.com/xudefa/go-boot-jwt"

	"github.com/xudefa/go-boot/boot"
	"github.com/xudefa/go-boot/condition"
	"github.com/xudefa/go-boot/constants"
	"github.com/xudefa/go-boot/core"
	"github.com/xudefa/go-boot/environment"
)

// JwtAutoConfiguration JWT 认证的自动配置
//
// 从 Environment 中读取 jwt.secret-key、jwt.issuer、jwt.expires-duration 等配置项，
// 创建 JWT 工具实例并注册到 IoC 容器中。
// 启用条件：jwt.enabled=true
type JwtAutoConfiguration struct{}

// init 注册 JWT 自动配置，由 jwt.enabled=true 条件控制
// Order=-100 确保在 Security 自动配置之前执行（Security 默认 Order=0）
func init() {
	boot.RegisterAutoConfigWith(&JwtAutoConfiguration{},
		boot.WithOrder(-100),
		boot.WithConditions(condition.OnProperty(constants.JWTEnabled, constants.ConditionTrue)),
	)
}

// Configure 执行自动配置逻辑，创建 JWT 工具并注册为 Bean
func (j *JwtAutoConfiguration) Configure(ctx boot.ApplicationContext) error {
	env := ctx.Environment()

	// 构建 JWT 配置选项
	opts := []jwtcore.JwtOptions{
		jwtcore.WithSecretKey(env.GetString(constants.JWTSecretKey, constants.DefaultJWTSecretKey)),
		jwtcore.WithIssuer(env.GetString(constants.JWTIssuer, constants.DefaultJWTIssuer)),
		jwtcore.WithExpiresDuration(time.Duration(env.GetInt(constants.JWTExpiresDuration, constants.DefaultJWTExpiresDuration)) * time.Second),
		jwtcore.WithRefreshExpiresDuration(time.Duration(env.GetInt(constants.JWTRefreshExpiresDuration, constants.DefaultJWTRefreshExpiresDuration)) * time.Second),
	}

	// 创建 JWT 工具实例
	jwtUtil := jwtcore.NewJWTUtil(opts...)

	// 注册到 IoC 容器
	if err := ctx.Register(constants.JWTUtilBeanID,
		core.Bean(jwtUtil),
		core.Singleton(),
	); err != nil {
		return err
	}

	// 注册 JWT 认证过滤器
	return j.registerJwtAuthenticationFilter(ctx, jwtUtil, env)
}

// registerJwtAuthenticationFilter 注册JWT认证过滤器到容器
func (j *JwtAutoConfiguration) registerJwtAuthenticationFilter(ctx boot.ApplicationContext, jwtUtil *jwtcore.JwtUtil, env *environment.Environment) error {
	container := ctx.Container()

	excludePaths := parseExcludePaths(env.GetString(constants.JWTExcludePaths, constants.DefaultJWTExcludePaths))

	jwtFilter := jwtcore.NewJwtAuthenticationFilter(jwtUtil, container, excludePaths)

	// 注册为 SecurityFilter 接口类型，以便 SecurityAutoConfiguration 能查找到
	if err := ctx.Register(constants.JWTAuthenticationFilterID,
		core.Bean(jwtFilter),
		core.Singleton(),
	); err != nil {
		return err
	}

	return nil
}

// parseExcludePaths 解析排除路径配置
func parseExcludePaths(value string) []string {
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
