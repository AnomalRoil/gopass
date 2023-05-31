package otp

import (
	"bytes"
	"context"
	"fmt"
	"github.com/kbinani/screenshot"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"image/png"
	"os"
	"strings"

	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/pquerna/otp"
)

// Calculate will compute a OTP code from a given secret.
//
//nolint:ireturn
func Calculate(name string, sec gopass.Secret) (*otp.Key, error) {
	otpURL := getOTPURL(sec)

	if otpURL != "" {
		debug.Log("found otpauth url: %s", out.Secret(otpURL))

		return otp.NewKeyFromURL(otpURL) //nolint:wrapcheck
	}

	// check KV entry and fall back to password if we don't have one

	// TOTP
	if secKey, found := sec.Get("totp"); found {
		return parseOTP("totp", secKey)
	}

	// HOTP
	if secKey, found := sec.Get("hotp"); found {
		return parseOTP("hotp", secKey)
	}

	debug.Log("no totp secret found, falling back to password")

	return parseOTP("totp", sec.Password())
}

func getOTPURL(sec gopass.Secret) string {
	// check if we have a key-value entry
	if url, found := sec.Get("otpauth"); found {
		if strings.HasPrefix(url, "//") {
			url = "otpauth:" + url
		}

		return url
	}

	// if there is no KV entry check the body
	for _, line := range strings.Split(sec.Body(), "\n") {
		if strings.HasPrefix(line, "otpauth://") {
			return line
		}
	}

	return ""
}

func parseOTP(typ string, secKey string) (*otp.Key, error) {
	if strings.HasPrefix(secKey, "otpauth://") {
		debug.Log("parsing otpauth:// URL %q", out.Secret(secKey))

		k, err := otp.NewKeyFromURL(secKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse otpauth URL: %w", err)
		}

		return k, nil
	}

	debug.Log("assembling otpauth URL from secret only (%q), using defaults", out.Secret(secKey))

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://%s/new?secret=%s&issuer=gopass", typ, secKey))
	if err != nil {
		debug.Log("failed to parse OTP: %s", out.Secret(secKey))

		return nil, fmt.Errorf("invalid OTP secret: %w", err)
	}

	return key, nil
}

// ParseScreen will attempt to parse all available screen and will look for otpauth QR codes. It returns the first one
// it has found.
func ParseScreen(ctx context.Context) (string, error) {
	var qr string
	for i := 0; i < screenshot.NumActiveDisplays(); i++ {
		out.Noticef(ctx, "Scanning screen n°%d", i)

		img, err := screenshot.CaptureDisplay(i)
		if err != nil {
			return "", err
		}

		out.OKf(ctx, "Area scanned on screen n°%d: %v", i, img.Bounds())
		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		if err != nil {
			return "", err
		}
		qrReader := qrcode.NewQRCodeReader()
		result, err := qrReader.Decode(bmp, nil)
		if err != nil {
			out.Warningf(ctx, "No QR code found while parsing screen n°%d.", i)

			continue
		}

		out.Noticef(ctx, "Found a qrcode, checking.")
		if strings.HasPrefix(result.GetText(), "otpauth://") {
			qr = result.GetText()
			out.OKf(ctx, "Found an otpauth:// QR code on screen n°%d (%v)", i, img.Bounds())

			break
		}
		out.Warningf(ctx, "Not an otpauth:// QR code, please make sure to only have your OTP qrcode displayed.")
	}

	return qr, nil
}

// WriteQRFile writes the given OTP code as a QR image to disk.
func WriteQRFile(key *otp.Key, file string) error {
	// Convert TOTP key into a QR code encoded as a PNG image.
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return fmt.Errorf("failed to encode qr code: %w", err)
	}

	if err := png.Encode(&buf, img); err != nil {
		return fmt.Errorf("failed to encode as png: %w", err)
	}

	if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write QR code: %w", err)
	}

	return nil
}

var (
	// ErrOathOTP is returned when the secret is not a valid OATH secret.
	ErrOathOTP = fmt.Errorf("QR codes can only be generated for OATH OTPs")
	// ErrType is returned when the secret is not a valid OTP type.
	ErrType = fmt.Errorf("type assertion failed")
)
