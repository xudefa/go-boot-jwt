# go-boot-jwt

[![Go Version](https://img.shields.io/github/go-mod/go-version/xudefa/go-boot-jwt)](https://go.dev/) [![License](https://img.shields.io/github/license/xudefa/go-boot-jwt)](./LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/xudefa/go-boot-jwt/test.yml?branch=master)](https://github.com/xudefa/go-boot-jwt/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/xudefa/go-boot-jwt.svg)](https://pkg.go.dev/github.com/xudefa/go-boot-jwt) [![Go Report Card](https://goreportcard.com/badge/github.com/xudefa/go-boot-jwt)](https://goreportcard.com/report/github.com/xudefa/go-boot-jwt)

基于 [go-boot](https://github.com/xudefa/go-boot) 的 JWT（JSON Web Token）认证集成模块。提供令牌生成、解析、验证和刷新功能，并内置 JWT 认证过滤器，可无缝集成到 go-boot 的安全体系中。

> 设计理念：遵循 go-boot 的开发规范，通过自动配置实现零代码 JWT 认证，支持函数式选项模式和依赖注入。

## 整体架构

```
┌───────────────────────────────────────────────────────────────────────┐
│                    go-boot ApplicationContext                         │
│  ┌───────────┐ ┌──────────────┐ ┌───────────┐ ┌───────────┐           │
│  │ Container │ │  Environment │ │ Lifecycle │ │ EventBus  │           │
│  └───────────┘ └──────────────┘ └───────────┘ └───────────┘           │
│                       ┌─────────────────────┐                         │
│                       │ AutoConfig Registry │                         │
│                       └─────────────────────┘                         │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │    go-boot-jwt Starter        │
                    │  ┌─────────────────────────┐  │
                    │  │ JwtUtil Bean            │  │
                    │  │ JwtAuthenticationFilter │  │
                    │  │ Token Generation        │  │
                    │  │ Token Validation        │  │
                    │  └─────────────────────────┘  │
                    └───────────────────────────────┘
```

## 目录

- [快速开始](#快速开始)
- [功能特性](#功能特性)
- [令牌操作](#令牌操作)
- [认证过滤器](#认证过滤器)
- [配置选项](#配置选项)
- [项目结构](#项目结构)
- [开发指南](#开发指南)
- [贡献](#贡献)
- [许可证](#许可证)

## 快速开始

### 安装

```bash
# 安装核心框架
go get github.com/xudefa/go-boot

# 安装 JWT 集成模块
go get github.com/xudefa/go-boot-jwt
```

### 最小示例

```go
package main

import (
    "github.com/xudefa/go-boot/boot"
    "github.com/xudefa/go-boot-jwt/jwt"
)

func main() {
    app, err := boot.NewApplication(
        boot.WithAppName("my-jwt-app"),
        boot.WithVersion("1.0.0"),
        boot.WithProperty("jwt.enabled", "true"),
        boot.WithProperty("jwt.secret-key", "my-secret-key"),
    )
    if err != nil {
        panic(err)
    }
    defer app.Stop()

    // 启动应用（自动配置 JWT）
    app.Start()

    // 获取 JwtUtil 进行令牌操作
    jwtUtil := app.Container().Get("jwtUtil").(*jwt.JwtUtil)
    
    // 生成令牌
    token, refreshToken, err := jwtUtil.GenerateToken("user123")
    if err != nil {
        panic(err)
    }
    
    // 验证令牌
    valid, err := jwtUtil.ValidateToken(token)
    if err != nil {
        panic(err)
    }
    
    // 等待终止信号
    app.WaitForSignal()
}
```

## 功能特性

| 特性 | 说明 |
|------|------|
| 令牌生成 | 支持访问令牌和刷新令牌生成 |
| 令牌解析 | 解析并验证 JWT 令牌的签名和声明 |
| 令牌刷新 | 使用刷新令牌获取新的访问令牌 |
| 自动配置 | 通过 `jwt.enabled=true` 自动启用 |
| 认证过滤器 | 内置 `JwtAuthenticationFilter` 实现请求认证 |
| 函数式选项 | 灵活的配置（密钥、签发者、过期时间等） |
| Bearer Token | 支持从 Authorization 头提取 Bearer Token |
| 依赖注入 | JwtUtil 和 Filter 自动注册为 Bean |

## 令牌操作

### 生成令牌

```go
jwtUtil := container.Get("jwtUtil").(*jwt.JwtUtil)

// 生成访问令牌和刷新令牌
token, refreshToken, err := jwtUtil.GenerateToken("user123")

// 带受众声明
token, refreshToken, err := jwtUtil.GenerateToken("user123", "api-service")
```

### 验证令牌

```go
// 验证令牌有效性
valid, err := jwtUtil.ValidateToken(token)

// 解析令牌获取声明
claims, err := jwtUtil.ParseToken(token)

// 获取用户名（Subject）
username, err := jwtUtil.GetSubject(token)

// 获取唯一标识（ID）
userId, err := jwtUtil.GetUserId(token)

// 获取剩余有效时间
remaining, err := jwtUtil.GetRemainingTime(token)
```

### 刷新令牌

```go
// 使用旧令牌刷新生成新令牌
newToken, newRefreshToken, err := jwtUtil.RefreshToken(oldToken)
```

## 认证过滤器

### 注册过滤器

JWT 认证过滤器会自动注册到容器中，类型为 `SecurityFilter`，可被 Security 自动配置发现和使用：

```go
// 自动配置会注册 JwtAuthenticationFilter
// 支持配置排除路径
jwt.exclude-paths: "/health,/swagger,/public"
```

### 提取 Bearer Token

```go
import "github.com/xudefa/go-boot-jwt/jwt"

// 从 Authorization 头提取 Token
authHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
token := jwt.ExtractBearerToken(authHeader)
// token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 配置选项

通过 `boot.WithProperty()` 或配置文件设置：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `jwt.enabled` | `false` | 是否启用 JWT 认证 |
| `jwt.secret-key` | `go-bootJwtSecret` | JWT 签名密钥 |
| `jwt.issuer` | `go-boot` | 令牌签发者 |
| `jwt.expires-duration` | `600` | 访问令牌过期时间（秒，最大 3600） |
| `jwt.refresh-expires-duration` | `3600` | 刷新令牌过期时间（秒） |
| `jwt.exclude-paths` | `` | 排除认证的路径（逗号分隔） |

### 示例配置

```yaml
# application.yml
jwt:
  enabled: true
  secret-key: my-super-secret-key
  issuer: my-app
  expires-duration: 1800
  refresh-expires-duration: 7200
  exclude-paths: "/health,/swagger,/api/public"
```

## 项目结构

```
go-boot-jwt/
├── jwt.go                  # JWT 工具类（令牌生成、解析、验证）
├── jwt_filter.go           # JWT 认证过滤器
├── builder.go              # 构建器辅助
├── autoconfig.go           # 自动配置注册
├── README.md
├── LICENSE
└── go.mod
```

## 开发指南

### 构建

```bash
go build ./...
```

### 测试

```bash
go test ./...
go test -cover ./...       # 带覆盖率
go test -race ./...        # 数据竞争检测
```

### 代码规范

```bash
go fmt ./...
golangci-lint run
```

## 贡献

欢迎提交 Issue 和 Pull Request！详细贡献指南请参阅 [CONTRIBUTING.md](./CONTRIBUTING.md)。

## 许可证

本项目采用 MIT 许可证 — 详情请参阅 [LICENSE](./LICENSE) 文件。