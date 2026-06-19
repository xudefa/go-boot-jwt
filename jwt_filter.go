package jwt

import (
	"context"
	"strings"

	"github.com/xudefa/go-boot/core"
	"github.com/xudefa/go-boot/security"
)

// JwtAuthenticationFilter JWT认证过滤器
// 从请求头中提取Bearer token并进行验证
type JwtAuthenticationFilter struct {
	jwtUtil      *JwtUtil
	container    core.Container // 延迟查找 UserDetailsService
	excludePaths []string
}

// NewJwtAuthenticationFilter 创建JWT认证过滤器
func NewJwtAuthenticationFilter(jwtUtil *JwtUtil, container core.Container, excludePaths []string) *JwtAuthenticationFilter {
	return &JwtAuthenticationFilter{
		jwtUtil:      jwtUtil,
		container:    container,
		excludePaths: excludePaths,
	}
}

// DoFilter 处理JWT认证，实现security.SecurityFilter接口
func (f *JwtAuthenticationFilter) DoFilter(ctx context.Context, request security.SecurityRequest, response security.SecurityResponse, chain security.SecurityFilterChain) error {
	// 检查是否在排除路径中
	if f.isExcluded(request.GetURI()) {
		return chain.DoFilter(ctx, request, response)
	}

	// 从Authorization头中提取Bearer token
	authHeader := request.GetHeader("Authorization")
	if authHeader == "" {
		return chain.DoFilter(ctx, request, response)
	}

	tokenString := ExtractBearerToken(authHeader)
	if tokenString == "" {
		return chain.DoFilter(ctx, request, response)
	}

	// 验证Token并获取用户信息
	claims, err := f.jwtUtil.ParseToken(tokenString)
	if err != nil {
		return err
	}

	// 通过 UserDetailsService 加载用户的完整角色信息
	userDetails := f.loadUserDetails(ctx, claims.Subject)
	if userDetails != nil {
		// 使用用户的真实角色创建已认证的Authentication
		authenticated := security.NewAuthenticatedUsernamePasswordAuthenticationToken(
			userDetails.Username(),
			userDetails.Authorities(),
		)
		security.SetAuthentication(authenticated)
	} else {
		// 如果无法加载用户详情，使用默认角色
		authenticated := security.NewAuthenticatedUsernamePasswordAuthenticationToken(claims.Subject, []string{"ROLE_USER"})
		security.SetAuthentication(authenticated)
	}

	return chain.DoFilter(ctx, request, response)
}

// loadUserDetails 从容器中获取 UserDetailsService 并加载用户详情
func (f *JwtAuthenticationFilter) loadUserDetails(ctx context.Context, username string) security.UserDetails {
	// 查找 UserDetailsService
	beans, err := f.container.GetAll((*security.UserDetailsService)(nil))
	if err != nil || len(beans) == 0 {
		return nil
	}

	// 尝试通过每个 UserDetailsService 加载用户
	for _, bean := range beans {
		if uds, ok := bean.(security.UserDetailsService); ok {
			userDetails, err := uds.LoadUserByUsername(ctx, username)
			if err == nil && userDetails != nil {
				return userDetails
			}
		}
	}
	return nil
}

// isExcluded 检查URI是否在排除列表中
func (f *JwtAuthenticationFilter) isExcluded(uri string) bool {
	for _, path := range f.excludePaths {
		if path == uri {
			return true
		}
		// 支持前缀匹配，如 /api/*
		if len(path) > 0 && path[len(path)-1] == '*' &&
			len(uri) >= len(path)-1 && strings.HasPrefix(uri, path[:len(path)-1]) {
			return true
		}
	}
	return false
}

// IsJwtFilter 标识这是一个JWT过滤器
func (f *JwtAuthenticationFilter) IsJwtFilter() bool {
	return true
}
