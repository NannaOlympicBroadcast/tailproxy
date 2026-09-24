package panel

import "github.com/NannaOlympicBroadcast/tailproxy/internal/token"

// MinTokenLen is the shortest token accepted from the environment or a file.
const MinTokenLen = token.MinLen

// LoadOrCreateToken: see token.LoadOrCreate.
func LoadOrCreateToken(path string) (string, bool, error) { return token.LoadOrCreate(path) }

// RotateToken: see token.Rotate.
func RotateToken(path string) (string, error) { return token.Rotate(path) }

// ReadTokenFile: see token.ReadFile.
func ReadTokenFile(path string) (string, error) { return token.ReadFile(path) }

func generateToken() (string, error) { return token.Generate() }
