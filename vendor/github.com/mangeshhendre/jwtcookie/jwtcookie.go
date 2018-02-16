package jwtcookie

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Monster is the struct that handles all this cookie nonsense.
type Monster struct {
	CookieName     string      // The name of the cookie to get/set
	RedirectSuffix string      // The authentication site to redirect to.
	RefreshSuffix  string      // The refresh site to use for cookie refresh.
	RemainingLife  int64       // The life in minutes which triggers refresh (below this number will refresh)
	CookieDomain   string      // The domain to set for the cookie.
	keyFunc        jwt.Keyfunc // a key function that will be passed in.
}

type option func(*Monster)

// New returns a fully initialized jwt cookie monster.
func New(options ...option) (*Monster, error) {
	m := Monster{
		CookieName:     "Bearer",
		RedirectSuffix: "windows",
		RefreshSuffix:  "token",
		RemainingLife:  5,
	}
	for _, opt := range options {
		opt(&m)
	}
	return &m, nil
}

// KeyFunc is a functional option which sets the cookie name.
func KeyFunc(keyFunc jwt.Keyfunc) option {
	return func(m *Monster) {
		m.keyFunc = keyFunc
	}
}

// CookieName is a functional option which sets the cookie name.
func CookieName(name string) option {
	return func(m *Monster) {
		m.CookieName = name
	}
}

// RedirectSuffix is a functional option which sets the redirect suffix.
func RedirectSuffix(name string) option {
	return func(m *Monster) {
		m.RedirectSuffix = name
	}
}

// RefreshSuffix is a functional option which sets the refresh suffix.
func RefreshSuffix(name string) option {
	return func(m *Monster) {
		m.RefreshSuffix = name
	}
}

// RemainingLife is a functional option which sets the lifetime threshold for a cookie refresh.
func RemainingLife(mins int64) option {
	return func(m *Monster) {
		m.RemainingLife = mins
	}
}

// JWTRedirect is a custom implementation of a redirect handler for safeguard properties.
func (m *Monster) JWTRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine the cookie domain dynamically.
		var host string
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		domainParts := strings.Split(host, ".")
		domainLen := len(domainParts)
		// grpclog.Printf("Host is %s, Length is %d, and cookie domain is %s\nRequest is %#v", host, domainLen, m.CookieDomain, r)
		m.CookieDomain = domainParts[domainLen-2] + "." + domainParts[domainLen-1]

		// First check for the cookie, if no cookie redirect and do not call the next one.
		c, err := r.Cookie(m.CookieName)
		if err != nil {
			// Could not retrieve the cookie, we need to redirect.
			m.RedirectToAuth(w, r)
			return
		}

		// Need to validate cookie.
		token, validToken := m.CheckToken(c.Value)
		if !validToken {
			m.RedirectToAuth(w, r)
			return
		}

		// Just do it no matter what.  Errors not really possible here.
		m.RefreshToken(w, token)

		// Yes I know that a bare string is silly.  We will make more better later.
		newRequest := r.WithContext(context.WithValue(r.Context(), "jwt", token))

		next.ServeHTTP(w, newRequest)
	})
}

// CheckToken is a method that will validate the token to see if it is valid and return that as a boolean.
func (m *Monster) CheckToken(tokenString string) (*jwt.Token, bool) {
	token, err := jwt.Parse(tokenString, m.keyFunc)
	// Watch the sense here, checking for NO error.
	if err == nil {
		if token.Valid {
			return token, true
		}
	}
	return nil, false
}

// RefreshToken is a method that will try to use the existing token to refresh.
func (m *Monster) RefreshToken(w http.ResponseWriter, t *jwt.Token) {

	// Should we refresh?
	plainClaims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		// The claims dont really look right.  How is this possible?
		return
	}

	expiration := expirationToInt64(plainClaims["exp"])

	// Do we have a useful expiration?
	// if (time.Now().Unix() - expiration) > (m.RemainingLife * 60) {
	if (expiration - time.Now().Unix()) > (m.RemainingLife * 60) {
		// No need to refresh
		return
	}

	// Setup the request.
	request, err := http.NewRequest("GET", fmt.Sprintf("https://authentication.%s/%s", m.CookieDomain, m.RefreshSuffix), nil)

	if err != nil {
		return
	}

	// Set our bearer.
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.Raw))

	// We should not need this, but maybe for the future.
	tlsConfig := &tls.Config{}

	// if *insecure {
	// 	tlsConfig.InsecureSkipVerify = true
	// }

	// Setup a transport for special handling of TLS.   May not need this anymore.
	tr := &http.Transport{TLSClientConfig: tlsConfig}

	// Setup a client using that transport.
	client := http.Client{Transport: tr}

	webResponse, err := client.Do(request)
	if err != nil {
		return
	}

	defer webResponse.Body.Close()

	switch webResponse.StatusCode {
	case http.StatusOK:
		break
	default:
		// Nothing I can do about it here.
		return
	}

	// Make a useful buffer.
	buffer := bytes.NewBuffer(nil)

	// Copy the web response into the body.
	io.Copy(buffer, webResponse.Body)

	// Is the token parseable.
	newToken, err := jwt.Parse(buffer.String(), m.keyFunc)
	if err != nil {
		return
	}

	// Is the token valid?
	if !newToken.Valid {
		return
	}

	// Are the claims valid
	claimsErr := newToken.Claims.Valid()
	if claimsErr != nil {
		return
	}

	// Get the claims
	claims, ok := newToken.Claims.(jwt.MapClaims)
	if !ok {
		// This is weird
		return
	}

	cookieExpiration := expirationToInt64(claims["exp"])

	// Set the cookie.
	cookie := &http.Cookie{
		Name:     "Bearer",
		Value:    buffer.String(),
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(cookieExpiration, 0),
		Domain:   m.CookieDomain,
		Path:     "/",
	}

	http.SetCookie(w, cookie)

}

func expirationToInt64(expiration interface{}) int64 {
	switch value := expiration.(type) {
	case float64:
		return int64(value)
	case json.Number:
		v, _ := value.Int64()
		return v
	}
	return 0
}

// RefreshCheck checks to see if the token requires refreshing.
func (m *Monster) RefreshCheck(t *jwt.Token) bool {
	// First we extract the expiration.
	plainClaims, ok := t.Claims.(jwt.MapClaims)
	if ok {
		// Ok the claims look like claims.  But can we dance.
		expiration, ok := plainClaims["exp"].(int64)
		if ok {
			// Ok the expiration is something we can work with..
			// Now does it have enough remaining life?
			if (time.Now().Unix() - expiration) < (m.RemainingLife * 60) {
				// We need to refresh.
				return true
			}
		}
	}
	return false
}

// RedirectToAuth is the function that returns a snippet of HTML to facilitate redirection to our authentication service.
func (m *Monster) RedirectToAuth(w http.ResponseWriter, r *http.Request) {
	// Ok, we are going to redirect to a site or something.
	redirectBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
    <head>
        <title>Unauthorized...</title>
    </head>
    <body>
        <p>You are not authorized to view this content.   Redirecting you to authenticate you.</p>
        <script>
            setTimeout(function(){
                window.location.href="https://authentication.%s/%s"; // The URL that will be redirected too.
            }, 2000); // The bigger the number the longer the delay.
        </script>
    </body>
</html>`, m.CookieDomain, m.RedirectSuffix)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(redirectBody))
}
