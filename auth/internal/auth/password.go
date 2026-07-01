package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultParams = argon2Params{
	memory:      64 * 1024, //64MiB
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

var (
	ErrInvalidHash         = errors.New("password hash is not in the expected format")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)

func HashPassword(password string) (string, error) {
	p := defaultParams

	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d, t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Key,
	)
	return encoded, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	p, salt, key, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	other := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if subtle.ConstantTimeCompare(key, other) == 1 {
		return true, nil
	}

	return false, nil
}

func decodeHash(encodedHash string) (argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return argon2Params{}, nil, nil, ErrIncompatibleVersion
	}

	var p argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}
	p.saltLength = uint32(len(salt))

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}
	p.keyLength = uint32(len(key))

	return p, salt, key, nil
}
