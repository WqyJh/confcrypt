// Copyright (c) 2023 Qiying Wang

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package confcrypt_test

import (
	"math/rand"
	"testing"
	"time"
	"unsafe"

	"github.com/WqyJh/confcrypt"

	"github.com/stretchr/testify/assert"
)

func encryptString(t *testing.T, s string, key string) string {
	encrypted, err := confcrypt.EncryptString(s, key)
	assert.NoError(t, err)
	return encrypted
}

func TestDecrypt(t *testing.T) {
	source := RandString(32)
	key := RandString(64)
	encrypted, err := confcrypt.Encrypt([]byte(source), key)
	assert.NoError(t, err)
	decrypted, err := confcrypt.Decrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, source, string(decrypted))
	assert.NotEqual(t, source, encrypted)
}

func TestDecode(t *testing.T) {
	type Nested struct {
		A string
		B []string
		C int
		D map[string][]string
	}
	type Config struct {
		A, B string
		C    int
		D    map[int]string
		E    map[string]Nested
		F    string
		G    []string
	}
	key := RandString(64)
	expected := Config{
		A: RandString(10),
		B: RandString(128),
		C: 1,
		D: map[int]string{
			2: RandString(20),
			8: RandString(44),
		},
		E: map[string]Nested{
			"a": {
				A: RandString(33),
				B: []string{RandString(10), RandString(20)},
				C: 1,
				D: map[string][]string{
					"b": {RandString(10), RandString(20)},
				},
			},
		},
		F: RandString(20),
		G: []string{RandString(10), RandString(20)},
	}
	origin := Config{
		A: encryptString(t, expected.A, key),
		B: encryptString(t, expected.B, key),
		C: expected.C,
		D: map[int]string{
			2: encryptString(t, expected.D[2], key),
			8: encryptString(t, expected.D[8], key),
		},
		E: map[string]Nested{
			"a": {
				A: encryptString(t, expected.E["a"].A, key),
				B: []string{
					encryptString(t, expected.E["a"].B[0], key),
					encryptString(t, expected.E["a"].B[1], key),
				},
				C: expected.E["a"].C,
				D: map[string][]string{
					"b": {
						encryptString(t, expected.E["a"].D["b"][0], key),
						encryptString(t, expected.E["a"].D["b"][1], key),
					},
				},
			},
		},
		F: expected.F,
		G: []string{
			encryptString(t, expected.G[0], key),
			expected.G[1],
		},
	}

	result, err := confcrypt.Decode(origin, key)
	assert.NoError(t, err)
	assert.NotEqual(t, result, origin)
	assert.Equal(t, expected, result)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}
