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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/webdav"
)

// 配置结构体
type Config struct {
	ssl        bool
	certFile   string
	keyFile    string
	addr       string
	rootDir    string
	username   string
	password   string
	blockDir   string
	blockFile  string
	sysLogFile string
	maxFail    int // 单IP最大失败次数
}

// IP认证错误记录器
type IPAuthTracker struct {
	mu                    sync.RWMutex
	failedCount           map[string]int
	blockedIPs            map[string]bool
	blockFile             string
	sysLogFile            string
	selfDestructThreshold int
	maxAttempts           int // 单IP失败次数阈值
}

// 只读文件系统包装器
type ReadOnlyFileSystem struct {
	webdav.FileSystem
}

// 初始化IP追踪器
func NewIPAuthTracker(blockFile, sysLogFile string, maxAttempts int) (*IPAuthTracker, error) {
	// 主动创建空的拉黑IP文件（若不存在）
	if _, err := os.Stat(blockFile); os.IsNotExist(err) {
		f, err := os.OpenFile(blockFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to create blacklist file: %v", err)
		}
		f.Close()
		log.Printf("Created empty blacklist file: %s", blockFile)
	}

	tracker := &IPAuthTracker{
		failedCount:           make(map[string]int),
		blockedIPs:            make(map[string]bool),
		blockFile:             blockFile,
		sysLogFile:            sysLogFile,
		selfDestructThreshold: 50,
		maxAttempts:           maxAttempts,
	}

	// 启动时加载已拉黑的IP
	if err := tracker.LoadBlockedIPs(); err != nil {
		return nil, fmt.Errorf("failed to load blacklist: %v", err)
	}

	// 检查初始拉黑IP数量是否已达阈值
	tracker.checkSelfDestruct()

	return tracker, nil
}

// 加载拉黑IP文件（Base64解码）
func (t *IPAuthTracker) LoadBlockedIPs() error {
	if _, err := os.Stat(t.blockFile); os.IsNotExist(err) {
		log.Printf("Blacklist file does not exist: %s", t.blockFile)
		return nil
	}

	data, err := os.ReadFile(t.blockFile)
	if err != nil {
		return fmt.Errorf("failed to read blacklist file: %v", err)
	}

	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		ipBytes, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			log.Printf("Base64 decode failed for line: %s, error: %v", string(line), err)
			continue
		}
		ipStr := string(ipBytes)
		t.mu.Lock()
		t.blockedIPs[ipStr] = true
		t.mu.Unlock()
		log.Printf("Loaded blacklisted IP: %s", ipStr)
	}
	log.Printf("Loaded %d blacklisted IPs", len(t.blockedIPs))
	return nil
}

// 保存拉黑IP到文件（Base64编码）
func (t *IPAuthTracker) SaveBlockedIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	encodedIP := base64.StdEncoding.EncodeToString([]byte(ip))

	f, err := os.OpenFile(t.blockFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open blacklist file: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(encodedIP + "\n"); err != nil {
		return fmt.Errorf("failed to write blacklist: %v", err)
	}

	t.mu.Lock()
	t.blockedIPs[ip] = true
	delete(t.failedCount, ip)
	t.mu.Unlock()

	log.Printf("IP %s blacklisted and saved", ip)
	t.checkSelfDestruct()
	return nil
}

// 检查拉黑IP数量是否达到自裁阈值
func (t *IPAuthTracker) checkSelfDestruct() {
	t.mu.RLock()
	blockedCount := len(t.blockedIPs)
	t.mu.RUnlock()

	if blockedCount >= t.selfDestructThreshold {
		logMsg := fmt.Sprintf("[%s] Under attack, self-destruct triggered. Blacklisted IPs: %d",
			time.Now().Format("2006-01-02 15:04:05"), blockedCount)
		f, err := os.OpenFile(t.sysLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(logMsg + "\n")
			f.Close()
		}
		log.Println(logMsg)
		log.Fatal("Self-destruct protection triggered, exiting.")
	}
}

// 记录认证失败并检查是否需要拉黑
func (t *IPAuthTracker) RecordFailedAuth(ip string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.blockedIPs[ip] {
		return true, nil
	}

	t.failedCount[ip]++
	count := t.failedCount[ip]
	log.Printf("IP %s authentication failures: %d", ip, count)

	if count >= t.maxAttempts {
		t.blockedIPs[ip] = true
		go func(ip string) {
			if err := t.SaveBlockedIP(ip); err != nil {
				log.Printf("Failed to save blacklisted IP: %v", err)
			}
		}(ip)
		log.Printf("IP %s blacklisted due to %d failures", ip, t.maxAttempts)
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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if before, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(before)
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	remoteAddr := r.RemoteAddr
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// 递归解码URL路径，防止双重编码绕过
func decodePathRecursively(encodedPath string) (string, error) {
	decoded, err := url.PathUnescape(encodedPath)
	if err != nil {
		return "", err
	}
	if decoded != encodedPath {
		return decodePathRecursively(decoded)
	}
	return decoded, nil
}

// 带IP拉黑的认证中间件
func authWithIPBlock(next http.Handler, validUser, validPass string, tracker *IPAuthTracker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		log.Printf("Request from %s, path: %s", clientIP, r.URL.Path)

		rawPath := r.URL.EscapedPath()
		if rawPath == "" {
			rawPath = r.URL.Path
		}
		safePath, err := decodePathRecursively(rawPath)
		if err != nil || strings.Contains(safePath, "..") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			log.Printf("Path traversal attempt blocked: %s -> %s", r.URL.Path, safePath)
			return
		}

		if tracker.IsBlocked(clientIP) {
			http.Error(w, "Please try again later", http.StatusForbidden)
			log.Printf("Blocked IP %s attempted access", clientIP)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != validUser || pass != validPass {
			isBlocked, _ := tracker.RecordFailedAuth(clientIP)
			if isBlocked {
				http.Error(w, "Please try again later", http.StatusForbidden)
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV Server"`)
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
			}
			return
		}

		tracker.mu.Lock()
		delete(tracker.failedCount, clientIP)
		tracker.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// 只读文件系统包装器
func (r *ReadOnlyFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return os.ErrPermission
}
func (r *ReadOnlyFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, os.ErrPermission
	}
	return r.FileSystem.OpenFile(ctx, name, os.O_RDONLY, perm)
}
func (r *ReadOnlyFileSystem) RemoveAll(ctx context.Context, name string) error {
	return os.ErrPermission
}
func (r *ReadOnlyFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	return os.ErrPermission
}
func (r *ReadOnlyFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return r.FileSystem.Stat(ctx, name)
}

func validateCredentials(username, password string) error {
	if len(username) < 6 {
		return fmt.Errorf("username must be at least 6 characters")
	}
	if len(password) < 14 {
		return fmt.Errorf("password must be at least 14 characters")
	}
	return nil
}

func main() {
	var config Config
	flag.BoolVar(&config.ssl, "ssl", false, "Enable SSL/TLS encryption")
	flag.StringVar(&config.certFile, "cert", "server.crt", "SSL certificate file")
	flag.StringVar(&config.keyFile, "key", "server.key", "SSL private key file")
	flag.StringVar(&config.addr, "addr", ":8080", "Listen address (must be in format :port)")
	flag.IntVar(&config.maxFail, "max-fail", 10, "Max authentication failures per IP before blacklisting")
	flag.Parse()

	// 检查 addr 格式：必须以 ":" 开头且后面为数字端口
	if !strings.HasPrefix(config.addr, ":") {
		log.Fatalf("Invalid listen address format: %s. Must be like :7047", config.addr)
	}
	portStr := config.addr[1:]
	if _, err := strconv.Atoi(portStr); err != nil {
		log.Fatalf("Port must be a number, got: %s", portStr)
	}

	config.username = "webdavuser"
	config.password = "71235*&^-12-NNjj_VVV"
	if err := validateCredentials(config.username, config.password); err != nil {
		log.Fatalf("Credential validation failed: %v", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 根目录（可自行修改）
	config.rootDir = "/home/aria"
	config.blockDir = filepath.Join(exeDir, "his_store_bak")
	config.blockFile = filepath.Join(config.blockDir, "blocked_ips.txt")
	config.sysLogFile = filepath.Join(exeDir, "sys.log")

	// 创建必要的目录
	if err := os.MkdirAll(config.rootDir, 0755); err != nil {
		log.Fatalf("Failed to create root directory: %v", err)
	}
	if err := os.MkdirAll(config.blockDir, 0755); err != nil {
		log.Fatalf("Failed to create blacklist directory: %v", err)
	}

	tracker, err := NewIPAuthTracker(config.blockFile, config.sysLogFile, config.maxFail)
	if err != nil {
		log.Fatalf("Failed to initialize IP tracker: %v", err)
	}

	fs := &ReadOnlyFileSystem{FileSystem: webdav.Dir(config.rootDir)}
	handler := &webdav.Handler{
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WebDAV error: %s %s -> %v", r.Method, r.URL.Path, err)
			}
		},
	}
	authHandler := authWithIPBlock(handler, config.username, config.password, tracker)

	log.Printf("=== WebDAV Server Configuration ===")
	log.Printf("Listen address: %s (dual-stack: IPv4 + IPv6)", config.addr)
	log.Printf("Root directory: %s", config.rootDir)
	log.Printf("SSL: %t", config.ssl)
	log.Printf("User: %s", config.username)
	log.Printf("Blacklist file: %s", config.blockFile)
	log.Printf("System log: %s", config.sysLogFile)
	log.Printf("Max failures per IP: %d", config.maxFail)
	log.Printf("Self-destruct threshold: %d IPs", tracker.selfDestructThreshold)
	log.Printf("Current blacklist count: %d", len(tracker.blockedIPs))
	log.Printf("==============================")

	// 提取端口（例如 :7047）
	port := config.addr

	// 启动服务器的辅助函数
	startServer := func(network, listenAddr string, useSSL bool) {
		// 如果是 OpenBSD，强制使用手动 Listener 模式以支持 IPv6 独立监听
		if runtime.GOOS == "openbsd" {
			srv := &http.Server{
				Addr:         listenAddr,
				Handler:      authHandler,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 0,
				IdleTimeout:  0,
			}

			var ln net.Listener
			var err error

			if network == "tcp6" {
				lc := net.ListenConfig{
					Control: func(network, address string, c syscall.RawConn) error {
						return c.Control(func(fd uintptr) {
							// OpenBSD 默认通常就是 1，这里显式设置确保万无一失
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
						})
					},
				}
				ln, err = lc.Listen(context.Background(), network, listenAddr)
			} else {
				ln, err = net.Listen(network, listenAddr)
			}

			if err != nil {
				log.Fatalf("%s 监听失败: %v", network, err)
			}

			if useSSL {
				srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				log.Printf("Starting %s (SSL) server on %s (OpenBSD mode)", network, listenAddr)
				if err := srv.ServeTLS(ln, config.certFile, config.keyFile); err != nil && err != http.ErrServerClosed {
					log.Fatalf("%s server error: %v", network, err)
				}
			} else {
				log.Printf("Starting %s (HTTP) server on %s (OpenBSD mode)", network, listenAddr)
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
					log.Fatalf("%s server error: %v", network, err)
				}
			}
			return // OpenBSD 逻辑结束，直接返回
		}

		// 非 OpenBSD 系统，维持你原来的逻辑
		srv := &http.Server{
			Addr:         listenAddr,
			Handler:      authHandler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 0,
			IdleTimeout:  0,
		}
		if useSSL {
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
			srv.TLSConfig = tlsConfig
			log.Printf("Starting %s (SSL) server on %s", network, listenAddr)
			if err := srv.ListenAndServeTLS(config.certFile, config.keyFile); err != nil {
				log.Fatalf("%s server error: %v", network, err)
			}
		} else {
			log.Printf("Starting %s (HTTP) server on %s", network, listenAddr)
			if err := srv.ListenAndServe(); err != nil {
				log.Fatalf("%s server error: %v", network, err)
			}
		}
	}

	// 双栈监听：分别使用 tcp4 和 tcp6
	if config.ssl {
		// 检查证书文件
		if _, err := os.Stat(config.certFile); os.IsNotExist(err) {
			log.Fatalf("SSL certificate file not found: %s", config.certFile)
		}
		if _, err := os.Stat(config.keyFile); os.IsNotExist(err) {
			log.Fatalf("SSL key file not found: %s", config.keyFile)
		}
		// IPv4 监听 (0.0.0.0:port)
		go startServer("tcp4", "0.0.0.0"+port, true)
		// IPv6 监听 ([::]:port) — 阻塞主 goroutine
		startServer("tcp6", "[::]"+port, true)
	} else {
		// HTTP 模式
		go startServer("tcp4", "0.0.0.0"+port, false)
		startServer("tcp6", "[::]"+port, false)
	}
}
