package confcrypt

import (
	"errors"
	"os"
	"reflect"
)

func DecodeInplace(v interface{}, key string) error {
	decoded, err := Decode(v, key)
	if err != nil {
		return err
	}
	if reflect.TypeOf(v).Kind() == reflect.Ptr {
		reflect.ValueOf(v).Elem().Set(reflect.ValueOf(decoded).Elem())
		return nil
	}
	reflect.ValueOf(v).Set(reflect.ValueOf(decoded))
	return nil
}

func DecodeByEnv(v interface{}, opts ...DecodeOption) error {
	o := defaultOption
	for _, opt := range opts {
		opt(&o)
	}
	key := os.Getenv(o.env)
	if key == "" {
		return ErrEmptyKey
	}
	return DecodeInplace(v, key)
}

var ErrEmptyKey = errors.New("empty key")

var defaultOption = decodeOption{
	env: "CONFIG_KEY",
}

type decodeOption struct {
	env string
}

type DecodeOption func(*decodeOption)

func WithEnv(env string) DecodeOption {
	return func(o *decodeOption) {
		o.env = env
	}
}
