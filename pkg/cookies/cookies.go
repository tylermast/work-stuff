package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

var (
	ErrValueTooLong = errors.New("Cookie value too long")
	ErrInvalidValue = errors.New("Invalid cookie value")
)

func WriteSigned(
	c echo.Context,
	cookie http.Cookie,
	secretKey []byte,
) error {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)

	cookie.Value = string(signature) + cookie.Value

	return write(c, cookie)
}

func ReadSigned(
	c echo.Context,
	name string,
	secretKey []byte,
) (string, error) {
	signedValue, err := read(c, name)
	if err != nil {
		return "", err
	}
	if len(signedValue) < sha256.Size {
		return "", ErrInvalidValue
	}

	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", ErrInvalidValue
	}

	return value, nil
}

func write(
	c echo.Context,
	cookie http.Cookie,
) error {
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))
	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}
	c.SetCookie(&cookie)
	return nil
}

func read(
	c echo.Context,
	name string,
) (string, error) {
	cookie, err := c.Cookie(name)
	if err != nil {
		return "", err
	}

	value, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	return string(value), nil
}
