# confcrypt [![GoDoc][doc-img]][doc]


Encrypt your sensitive data in config file and decrypt it at runtime.

## Get

```bash
go get -u "github.com/WqyJh/confcrypt"
```

## Usage

Use any random string as your config `key`.

Use `EncryptString` to encrypt all of your sensitive data one by one.

```go
var (
	key = "12345678"
)

func TestEncrypt(t *testing.T) {
	plain := "hello"
	encrypted, err := confcrypt.EncryptString(plain, key)
	assert.NoError(t, err)
	t.Logf("encrypted: '%s'", encrypted)

	decrypted, err := confcrypt.Decrypt(encrypted[4:], key)
	assert.NoError(t, err)
	t.Logf("decrypted: '%s'", decrypted)
}

func TestDecrypt(t *testing.T) {
	encrypted := "ENC~tSbCaeksELsWsw9+eXADFTRONqOTiPkL6q5yRW8Wp4Um"
	decrypted, err := confcrypt.Decrypt(encrypted[4:], key)
	assert.NoError(t, err)
	t.Logf("decrypted: '%s'", decrypted)
}
```

Replace all of your sensitive data in your config with the encrypted string, which should start with `ENC~`.

And use `Decrypt` to decrypt the encrypted string without `ENC~` prefix.

It's recommended to use `Decode` to decrypt all encrypted string fields in a struct.

For example, assume you have config struct as below:

```go
type AppConfig {
    Id string
    Secret string
}
type Config struct {
    User string
    Password string
    App AppConfig
}
```

You load it from config file and got:

```go
cfg := Config{
    User: "foo",
    Password: "ENC~xxxxxxxxxxxxxxxxxxxxx",
    App: AppConfig{
        Id: "bar",
        Secret: "ENC~yyyyyyyyyyyyyyyyyyyy",
    },
}
```

Then use `Decode` to decrypt the encrypted fields including `Password` and `Secret`.

```go
result, err := confcrypt.Decode(&cfg, key)
// result.Password is decrypted
// result.App.Secret is decrypted
```

## License

Released under the [MIT License](LICENSE).

[doc-img]: https://godoc.org/github.com/WqyJh/confcrypt?status.svg
[doc]: https://godoc.org/github.com/WqyJh/confcrypt
