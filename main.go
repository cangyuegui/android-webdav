package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/net/webdav"
)

// 配置结构体
type Config struct {
	ssl      bool
	certFile string
	keyFile  string
	addr     string
	rootDir  string
	username string
	password string
}

// 只读文件系统包装器，禁用所有写操作（适配新版API）
type ReadOnlyFileSystem struct {
	webdav.FileSystem
}

// 重写Mkdir方法，返回权限错误（新版API使用context.Context）
func (r *ReadOnlyFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return os.ErrPermission
}

// 重写OpenFile方法，仅允许只读模式
func (r *ReadOnlyFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// 禁止所有写操作相关的flag
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, os.ErrPermission
	}
	// 强制以只读模式打开
	return r.FileSystem.OpenFile(ctx, name, os.O_RDONLY, perm)
}

// 重写RemoveAll方法，返回权限错误
func (r *ReadOnlyFileSystem) RemoveAll(ctx context.Context, name string) error {
	return os.ErrPermission
}

// 重写Rename方法，返回权限错误
func (r *ReadOnlyFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	return os.ErrPermission
}

// 重写Stat方法，保持原有功能
func (r *ReadOnlyFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return r.FileSystem.Stat(ctx, name)
}

// 验证账号密码长度
func validateCredentials(username, password string) error {
	if len(username) < 6 {
		return fmt.Errorf("用户名长度不能少于6个字符")
	}
	if len(password) < 14 {
		return fmt.Errorf("密码长度不能少于14个字符")
	}
	return nil
}

// 基本认证中间件
func basicAuth(next http.Handler, validUser, validPass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != validUser || pass != validPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
			http.Error(w, "认证失败", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 定义命令行参数
	var config Config
	flag.BoolVar(&config.ssl, "ssl", false, "是否启用SSL/TLS加密 (true/false)")
	flag.StringVar(&config.certFile, "cert", "server.crt", "SSL证书文件路径 (启用SSL时必填)")
	flag.StringVar(&config.keyFile, "key", "server.key", "SSL私钥文件路径 (启用SSL时必填)")
	flag.StringVar(&config.addr, "addr", ":8080", "服务器监听地址")
	flag.Parse()

	// 内置账号密码（满足长度要求：用户6位+，密码14位+）
	config.username = "aloofuser"
	config.password = "78.$%#1@12345688_*"

	// 验证内置账号密码长度
	if err := validateCredentials(config.username, config.password); err != nil {
		log.Fatalf("账号密码验证失败: %v", err)
	}

	// 获取当前可执行文件目录
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取可执行文件路径失败: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 设置WebDAV根目录为可执行文件同级的FILES文件夹
	config.rootDir = filepath.Join(exeDir, "FILES")

	// 检查FILES目录是否存在，不存在则创建（权限0755：只读给其他用户，可读写给所有者）
	if _, err := os.Stat(config.rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(config.rootDir, 0755); err != nil {
			log.Fatalf("创建FILES目录失败: %v", err)
		}
		log.Printf("已创建FILES目录: %s", config.rootDir)
	}

	// 创建只读文件系统实例
	fs := &ReadOnlyFileSystem{
		FileSystem: webdav.Dir(config.rootDir),
	}

	// 配置WebDAV处理器（适配新版API）
	handler := &webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WebDAV操作错误: %s %s -> %v", r.Method, r.URL.Path, err)
			}
		},
	}

	// 包装认证中间件，强制所有请求必须认证
	authHandler := basicAuth(handler, config.username, config.password)

	// 打印启动信息
	log.Printf("=== WebDAV 服务器启动配置 ===")
	log.Printf("监听地址: %s", config.addr)
	log.Printf("文件根目录: %s", config.rootDir)
	log.Printf("SSL加密: %t", config.ssl)
	log.Printf("认证用户: %s", config.username)
	log.Printf("==============================")

	// 根据SSL配置启动服务器
	if config.ssl {
		// 检查SSL证书/私钥文件是否存在
		if _, err := os.Stat(config.certFile); os.IsNotExist(err) {
			log.Fatalf("SSL证书文件不存在: %s", config.certFile)
		}
		if _, err := os.Stat(config.keyFile); os.IsNotExist(err) {
			log.Fatalf("SSL私钥文件不存在: %s", config.keyFile)
		}

		// 配置TLS（强制TLS 1.2+，提升安全性）
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		server := &http.Server{
			Addr:      config.addr,
			Handler:   authHandler,
			TLSConfig: tlsConfig,
		}

		log.Println("启动HTTPS WebDAV服务器（SSL加密）")
		log.Fatal(server.ListenAndServeTLS(config.certFile, config.keyFile))
	} else {
		log.Println("启动HTTP WebDAV服务器（非加密）")
		log.Fatal(http.ListenAndServe(config.addr, authHandler))
	}
}
