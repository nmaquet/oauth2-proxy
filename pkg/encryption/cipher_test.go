package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretBase64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretBase64)
	assert.Equal(t, nil, err)
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestEncodeIntoAndDecodeIntoAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	token := "my access token"
	originalToken := token

	assert.Equal(t, nil, c.EncryptInto(&token))
	assert.NotEqual(t, originalToken, token)

	assert.Equal(t, nil, c.DecryptInto(&token))
	assert.Equal(t, originalToken, token)

	// Check no errors with empty or nil strings
	empty := ""
	assert.Equal(t, nil, c.EncryptInto(&empty))
	assert.Equal(t, nil, c.DecryptInto(&empty))
	assert.Equal(t, nil, c.EncryptInto(nil))
	assert.Equal(t, nil, c.DecryptInto(nil))
}
