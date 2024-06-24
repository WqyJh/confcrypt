package confcrypt_test

import (
	"os"
	"testing"

	"github.com/WqyJh/confcrypt"
	"github.com/stretchr/testify/assert"
)

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

func getData(t *testing.T, key string) (origin Config, expected Config) {
	t.Helper()

	expected = Config{
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
	origin = Config{
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
	return
}

func TestDecodeInplace(t *testing.T) {
	key := RandString(64)
	origin, expected := getData(t, key)
	assert.NotEqual(t, expected, origin)
	err := confcrypt.DecodeInplace(&origin, key)
	assert.NoError(t, err)
	assert.Equal(t, expected, origin)
}

func TestDecodeByEnv(t *testing.T) {
	key := RandString(64)
	origin, expected := getData(t, key)
	assert.NotEqual(t, expected, origin)

	err := confcrypt.DecodeByEnv(&origin)
	assert.Equal(t, confcrypt.ErrEmptyKey, err)

	os.Setenv("CONFIG_KEY", key)
	err = confcrypt.DecodeByEnv(&origin)
	assert.NoError(t, err)
	assert.Equal(t, expected, origin)

	// reinitialize
	origin, expected = getData(t, key)
	assert.NotEqual(t, expected, origin)
	err = confcrypt.DecodeByEnv(&origin, confcrypt.WithEnv("CONFIG_KEY_2"))
	assert.Equal(t, confcrypt.ErrEmptyKey, err)

	os.Setenv("CONFIG_KEY_2", key)
	err = confcrypt.DecodeByEnv(&origin, confcrypt.WithEnv("CONFIG_KEY_2"))
	assert.NoError(t, err)
	assert.Equal(t, expected, origin)
}
