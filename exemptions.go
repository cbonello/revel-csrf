// Package csrf is a synchronizer Token Pattern implementation.
//
// Management of routes exempted from CSRF checks.
package csrf

import (
	"fmt"
	pathPackage "path"
	"sync"

	"github.com/revel/revel"
)

// I'm not cetain that we need a mutex because exempted routes are generally
// configured when the application starts and the list is read-only after.
type globPath struct {
	sync.RWMutex
	list []string
}

var (
	exemptionsFullPath = struct {
		sync.RWMutex
		list map[string]struct{}
	}{
		list: make(map[string]struct{}),
	}

	exemptionsGlobs globPath
)

// IsExempted checks whether given path is exempt from CSRF checks or not.
func IsExempted(path string) bool {
	exemptionsFullPath.RLock()
	_, found := exemptionsFullPath.list[path]
	exemptionsFullPath.RUnlock()
	if found {
		revel.AppLog.Infof("REVEL-CSRF: Ignoring exempted route '%s'...\n", path)
		return true
	}

	for _, glob := range exemptionsGlobs.list {
		exemptionsGlobs.RLock()
		found, err := pathPackage.Match(glob, path)
		exemptionsGlobs.RUnlock()
		if err != nil {
			// See http://golang.org/pkg/path/#Match for error description.
			panic(fmt.Sprintf("REVEL-CSRF: malformed glob pattern: %#v", err))
		}
		if found {
			revel.AppLog.Infof("REVEL-CSRF: Ignoring exempted route '%s'...", path)
			return true
		}
	}
	return false
}

// ExemptedFullPath exempts one exact path from CSRF checks.
func ExemptedFullPath(path string) {
	revel.AppLog.Infof("REVEL-CSRF: Adding exemption '%s'...\n", path)
	exemptionsFullPath.Lock()
	exemptionsFullPath.list[path] = struct{}{}
	exemptionsFullPath.Unlock()
}

// ExemptedFullPath exempts exact paths from CSRF checks.
func ExemptedFullPaths(paths ...string) {
	for _, v := range paths {
		ExemptedFullPath(v)
	}
}

// ExemptedGlob exempts one path from CSRF checks using pattern matching.
// See http://golang.org/pkg/path/#Match
func ExemptedGlob(path string) {
	revel.AppLog.Infof("REVEL-CSRF: Adding exemption GLOB '%s'...\n", path)
	exemptionsGlobs.Lock()
	exemptionsGlobs.list = append(exemptionsGlobs.list, path)
	exemptionsGlobs.Unlock()
}

// ExemptedGlobs exempts paths from CSRF checks using pattern matching.
func ExemptedGlobs(paths ...string) {
	for _, v := range paths {
		ExemptedGlob(v)
	}
}
