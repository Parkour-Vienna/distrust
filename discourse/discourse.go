package discourse

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"

	"github.com/pkg/errors"
)

type SSOConfig struct {
	Server string
	Secret string
}

func GenerateURL(server, callback, key string, nonce int) string {
	payload := fmt.Sprintf("nonce=%d&return_sso_url=%s", nonce, callback)
	rk := []byte(key)
	bpl := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	base64.StdEncoding.Encode(bpl, []byte(payload))
	h := hmac.New(sha256.New, rk)
	h.Write(bpl)

	return fmt.Sprintf("%s/session/sso_provider?sso=%s&sig=%s",
		server,
		string(bpl),
		hex.EncodeToString(h.Sum(nil)))
}

func ValidateResponse(sso, sig, key string, nonce int) (url.Values, error) {
	rk := []byte(key)
	h := hmac.New(sha256.New, rk)
	h.Write([]byte(sso))

	rsig, err := hex.DecodeString(sig)
	if err != nil {
		return nil, errors.Wrap(err, "decoding signature")
	}

	if !bytes.Equal(h.Sum(nil), rsig) {
		return nil, errors.New("wrong signature from discourse")
	}

	qs, err := base64.StdEncoding.DecodeString(sso)
	if err != nil {
		return nil, errors.Wrap(err, "decoding discourse payload")
	}
	values, err := url.ParseQuery(string(qs))
	if err != nil {
		return nil, errors.Wrap(err, "parsing discourse payload")
	}

	rnonce, err := strconv.Atoi(values.Get("nonce"))
	if err != nil {
		return nil, errors.Wrap(err, "parsing returned nonce")
	}

	if rnonce != nonce {
		return nil, errors.New("wrong nonce from discourse")
	}

	return values, nil
}
