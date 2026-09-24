// Package token creates, persists and validates access tokens (panel and
// relay): 32 random bytes, stored in a 0600 file.
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MinLen is the shortest token accepted from the environment or a file.
const MinLen = 16

// Generate returns 32 random bytes, base64url-encoded (43 characters).
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate panel token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// LoadOrCreate returns the token stored at path. If the file does not
// exist, a new token is generated and written with mode 0600; created reports
// whether that happened. A file readable by group or others is refused.
func LoadOrCreate(path string) (token string, created bool, err error) {
	token, err = readTokenFile(path)
	if err == nil {
		return token, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	token, err = Generate()
	if err != nil {
		return "", false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) { // created concurrently: use that one
		token, err = readTokenFile(path)
		return token, false, err
	}
	if err != nil {
		return "", false, fmt.Errorf("create token file: %w", err)
	}
	_, werr := f.WriteString(token + "\n")
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(path)
		return "", false, fmt.Errorf("write token file: %w", err)
	}
	return token, true, nil
}

// Rotate replaces the token stored at path with a new random token and
// returns it. A running process keeps using its old token until restarted.
func Rotate(path string) (string, error) {
	token, err := Generate()
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	_, werr := tmp.WriteString(token + "\n")
	if err := errors.Join(werr, tmp.Sync(), tmp.Close()); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return token, nil
}

// ReadFile returns the token stored at path, applying the same checks
// as LoadOrCreate.
func ReadFile(path string) (string, error) { return readTokenFile(path) }

func readTokenFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("令牌文件 %s 的权限是 %#o，其他用户也能读取；请执行 chmod 600 %s 后再启动", path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < MinLen || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("令牌文件 %s 的内容无效（需要至少 %d 个字符、不含空白）；可以删除它，或用对应的 token --rotate 命令重新生成", path, MinLen)
	}
	return token, nil
}
