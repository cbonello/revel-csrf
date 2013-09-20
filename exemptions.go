// Management of routes exempted from CSRF checks.
package csrf

import (
	"github.com/golang/glog"
	"fmt"
	pathPackage "path"
	"sync"
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
	} {
			list: make(map[string]struct{}),
		}

	exemptionsGlobs globPath
)

// Checks if given path is exempt from CSRF checks.
func IsExempted(path string) bool {
	exemptionsFullPath.RLock()
	_, found := exemptionsFullPath.list[path]
	exemptionsFullPath.RUnlock()
	if found {
		glog.V(2).Infof("REVEL-CSRF: Ignoring exempted route '%s'...", path)
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
			glog.V(2).Infof("REVEL-CSRF: Ignoring exempted route '%s'...", path)
			return true
		}
	}
	return false
}

// Exempts an exact path from CSRF checks.
func ExemptedFullPath(path string) {
	glog.V(2).Infof("REVEL-CSRF: Adding exemption '%s'...", path)
	exemptionsFullPath.Lock()
	exemptionsFullPath.list[path] = struct{}{}
	exemptionsFullPath.Unlock()
}

func ExemptedFullPaths(paths ...string) {
	for _, v := range paths {
		ExemptedFullPath(v)
	}
}

// Exempts a path from CSRF checks using pattern matching.
// See http://golang.org/pkg/path/#Match
func ExemptedGlob(path string) {
	glog.V(2).Infof("REVEL-CSRF: Adding exemption GLOB '%s'...", path)
	exemptionsGlobs.Lock()
	exemptionsGlobs.list = append(exemptionsGlobs.list, path)
	exemptionsGlobs.Unlock()
}

func ExemptedGlobs(paths ...string) {
	for _, v := range paths {
		ExemptedGlob(v)
	}
}
