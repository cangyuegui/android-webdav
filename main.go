package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/net/webdav"
)

// 配置结构体
type Config struct {
	ssl       bool
	certFile  string
	keyFile   string
	addr      string
	rootDir   string
	username  string
	password  string
	blockDir  string // 拉黑IP存储目录
	blockFile string // 拉黑IP存储文件
}

// IP认证错误记录器
type IPAuthTracker struct {
	mu          sync.RWMutex
	failedCount map[string]int  // IP -> 失败次数
	blockedIPs  map[string]bool // 已拉黑IP
	blockFile   string          // 拉黑IP存储文件路径
}

// 只读文件系统包装器，禁用所有写操作（适配新版API）
type ReadOnlyFileSystem struct {
	webdav.FileSystem
}

// 初始化IP追踪器
func NewIPAuthTracker(blockFile string) (*IPAuthTracker, error) {
	tracker := &IPAuthTracker{
		failedCount: make(map[string]int),
		blockedIPs:  make(map[string]bool),
		blockFile:   blockFile,
	}

	// 启动时加载已拉黑的IP
	if err := tracker.LoadBlockedIPs(); err != nil {
		return nil, fmt.Errorf("加载拉黑IP失败: %v", err)
	}

	return tracker, nil
}

// 加载拉黑IP文件（Base64解码）
func (t *IPAuthTracker) LoadBlockedIPs() error {
	// 检查文件是否存在
	if _, err := os.Stat(t.blockFile); os.IsNotExist(err) {
		log.Printf("拉黑IP文件不存在，将创建新文件: %s", t.blockFile)
		return nil
	}

	// 读取文件内容
	data, err := os.ReadFile(t.blockFile)
	if err != nil {
		return fmt.Errorf("读取拉黑IP文件失败: %v", err)
	}

	// 按行解析（每行一个Base64编码的IP）
	lines := []byte(data)
	var ipStr string
	for len(lines) > 0 {
		// 分割行
		n := len(lines)
		if i := bytes.IndexByte(lines, '\n'); i >= 0 {
			n = i
		}
		line := lines[:n]
		lines = lines[n+1:]

		// 跳过空行
		if len(line) == 0 {
			continue
		}

		// Base64解码
		ipBytes, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			log.Printf("Base64解码IP失败，跳过该行: %s, 错误: %v", string(line), err)
			continue
		}

		ipStr = string(ipBytes)
		t.mu.Lock()
		t.blockedIPs[ipStr] = true
		t.mu.Unlock()
		log.Printf("加载拉黑IP: %s", ipStr)
	}

	log.Printf("共加载 %d 个拉黑IP", len(t.blockedIPs))
	return nil
}

// 保存拉黑IP到文件（Base64编码）
func (t *IPAuthTracker) SaveBlockedIP(ip string) error {
	// Base64编码IP
	encodedIP := base64.StdEncoding.EncodeToString([]byte(ip))

	// 追加写入文件（每行一个）
	f, err := os.OpenFile(t.blockFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开拉黑IP文件失败: %v", err)
	}
	defer f.Close()

	_, err = f.WriteString(encodedIP + "\n")
	if err != nil {
		return fmt.Errorf("写入拉黑IP文件失败: %v", err)
	}

	// 更新内存中的拉黑列表
	t.mu.Lock()
	t.blockedIPs[ip] = true
	// 清除该IP的失败次数
	delete(t.failedCount, ip)
	t.mu.Unlock()

	log.Printf("IP已拉黑并保存: %s (Base64: %s)", ip, encodedIP)
	return nil
}

// 记录认证失败并检查是否需要拉黑（三次失败拉黑）
func (t *IPAuthTracker) RecordFailedAuth(ip string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 检查是否已拉黑
	if t.blockedIPs[ip] {
		return true, nil
	}

	// 增加失败次数
	t.failedCount[ip]++
	count := t.failedCount[ip]
	log.Printf("IP %s 认证失败次数: %d", ip, count)

	// 三次失败则拉黑
	if count >= 3 {
		t.blockedIPs[ip] = true
		// 异步保存到文件（避免阻塞请求）
		go func(ip string) {
			if err := t.SaveBlockedIP(ip); err != nil {
				log.Printf("保存拉黑IP失败: %v", err)
			}
		}(ip)
		log.Printf("IP %s 因三次认证失败被永久拉黑", ip)
		return true, nil
	}

	return false, nil
}

// 检查IP是否被拉黑
func (t *IPAuthTracker) IsBlocked(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.blockedIPs[ip]
}

// 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 优先获取X-Forwarded-For（反向代理场景）
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// 取第一个IP
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	// 其次获取X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 直接获取远程地址
	remoteAddr := r.RemoteAddr
	// 解析IP:端口
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// 带IP拉黑的认证中间件
func authWithIPBlock(next http.Handler, validUser, validPass string, tracker *IPAuthTracker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. 获取客户端IP
		clientIP := getClientIP(r)
		log.Printf("收到请求，客户端IP: %s, 路径: %s", clientIP, r.URL.Path)

		// 2. 检查IP是否被拉黑
		if tracker.IsBlocked(clientIP) {
			http.Error(w, "请继续再次尝试连接", http.StatusForbidden)
			log.Printf("拉黑IP %s 尝试访问，已拒绝", clientIP)
			return
		}

		// 3. 验证账号密码
		user, pass, ok := r.BasicAuth()
		if !ok || user != validUser || pass != validPass {
			// 记录认证失败
			isBlocked, err := tracker.RecordFailedAuth(clientIP)
			if err != nil {
				log.Printf("记录认证失败失败: %v", err)
			}

			// 拉黑则返回403，否则返回401
			if isBlocked {
				http.Error(w, "请继续再次尝试连接，重试连接", http.StatusForbidden)
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
				http.Error(w, "认证失败", http.StatusUnauthorized)
			}
			return
		}

		// 4. 认证成功，清除失败次数
		tracker.mu.Lock()
		delete(tracker.failedCount, clientIP)
		tracker.mu.Unlock()

		// 5. 处理请求
		next.ServeHTTP(w, r)
	})
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

	// 设置拉黑IP存储目录和文件（exe同级/his_store_bak/blocked_ips.txt）
	config.blockDir = filepath.Join(exeDir, "his_store_bak")
	config.blockFile = filepath.Join(config.blockDir, "blocked_ips.txt")

	// 检查FILES目录是否存在，不存在则创建
	if _, err := os.Stat(config.rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(config.rootDir, 0755); err != nil {
			log.Fatalf("创建FILES目录失败: %v", err)
		}
		log.Printf("已创建FILES目录: %s", config.rootDir)
	}

	// 检查拉黑IP目录是否存在，不存在则创建
	if _, err := os.Stat(config.blockDir); os.IsNotExist(err) {
		if err := os.MkdirAll(config.blockDir, 0755); err != nil {
			log.Fatalf("创建拉黑IP目录失败: %v", err)
		}
		log.Printf("已创建拉黑IP目录: %s", config.blockDir)
	}

	// 初始化IP认证追踪器
	tracker, err := NewIPAuthTracker(config.blockFile)
	if err != nil {
		log.Fatalf("初始化IP追踪器失败: %v", err)
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

	// 包装带IP拉黑的认证中间件
	authHandler := authWithIPBlock(handler, config.username, config.password, tracker)

	// 打印启动信息
	log.Printf("=== WebDAV 服务器启动配置 ===")
	log.Printf("监听地址: %s", config.addr)
	log.Printf("文件根目录: %s", config.rootDir)
	log.Printf("SSL加密: %t", config.ssl)
	log.Printf("认证用户: %s", config.username)
	log.Printf("拉黑IP存储文件: %s", config.blockFile)
	log.Printf("当前拉黑IP数量: %d", len(tracker.blockedIPs))
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
