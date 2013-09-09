// Synchronizer Token Pattern implementation.
//
// See [OWASP] https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
package csrf

import (
	"crypto/subtle"
	"github.com/robfig/revel"
	"net/url"
	"regexp"
)

const (
	cookieName = "csrf_token"
	fieldName  = "csrf_token"
	headerName = "X-CSRF-Token"
)

var (
	errNoReferer  = "A secure request contained no Referer or its value was malformed."
	errBadReferer = "Same-origin policy failure."
	errBadToken   = "CSRF tokens mismatch."
)

var CSRFFilter = func(c *revel.Controller, fc []revel.Filter) {
	r := c.Request.Request

	// OWASP; General Recommendation: Synchronizer Token Pattern.
	// CSRF tokens must be associated with the user's current session.
	tokenCookie, found := c.Session[cookieName]
	realToken := ""
	if !found {
		realToken = generateNewToken(c)
	} else {
		realToken = tokenCookie
		revel.TRACE.Printf("Session's CSRF token: '%s'", realToken)
		if len(realToken) != tokenLength {
			// Wrong length; token has either been tampered with, we're migrating
			// onto a new algorithm for generating tokens, or a new session has
			// been initiated. In any case, a new token is generated and the
			// error will be detected later.
			revel.TRACE.Printf("Bad CSRF token length: found %d, expected %d",
				len(realToken), tokenLength)
			realToken = generateNewToken(c)
		}
	}

	c.RenderArgs[fieldName] = realToken

	// See http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods
	safeMethod, _ := regexp.MatchString("^(GET|HEAD|OPTIONS|TRACE)$", r.Method)
	if !safeMethod {
		revel.TRACE.Printf("Unsafe %s method...", r.Method)
		if r.URL.Scheme == "https" {
			// See OWASP; Checking the Referer Header.
			referer, err := url.Parse(r.Header.Get("Referer"))
			if err != nil || referer.String() == "" {
				// Parse error or empty referer.
				c.Result = c.Forbidden(errNoReferer)
				return
			}
			// See OWASP; Checking the Origin Header.
			if !sameOrigin(referer, r.URL) {
				c.Result = c.Forbidden(errBadReferer)
				return
			}
		}

		// Accept CSRF token in the custom HTTP header X-CSRF-Token, as well as
		// in the form submission itself, for ease of use with popular JavaScript
		// toolkits which allow insertion of custom headers into all AJAX
		// requests. See http://erlend.oftedal.no/blog/?blogid=118
		sentToken := r.Header.Get(headerName)
		if sentToken == "" {
			sentToken = c.Params.Get(fieldName)
		}
		revel.TRACE.Printf("CSRF token received: '%s'", sentToken)

		if len(sentToken) != len(realToken) {
			c.Result = c.Forbidden(errBadToken)
			return
		} else {
			comparison := subtle.ConstantTimeCompare([]byte(sentToken), []byte(realToken))
			if comparison != 1 {
				c.Result = c.Forbidden(errBadToken)
				return
			}
		}
	}
	revel.TRACE.Println("CSRF token successfully checked.")

	fc[0](c, fc[1:])
}

// See http://en.wikipedia.org/wiki/Same-origin_policy
func sameOrigin(u1, u2 *url.URL) bool {
	return (u1.Scheme == u2.Scheme && u1.Host == u2.Host)
}

// Generate a new CSRF token.
func generateNewToken(c *revel.Controller) string {
	token := generateToken()
	revel.TRACE.Printf("Generated new CSRF Token: '%s'", token)
	c.Session[cookieName] = token
	return token
}
