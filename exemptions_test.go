package csrf

import (
	"testing"
)

func TestExemptedFullPath(t *testing.T) {
	//hand := New(nil)
	path := "/Hello"

	ExemptedFullPath(path)
	if !IsExempted(path) {
		t.Errorf("%v is not exempted, but it should be", path)
	}

	other := "/Goodbye"
	if IsExempted(other) {
		t.Errorf("%v is exempted, but it shouldn't be", other)
	}
}

func TestExemptedFullPaths(t *testing.T) {
	//hand := New(nil)
	paths := []string{"/home", "/news", "/help"}
	ExemptedFullPaths(paths...)

	for _, v := range paths {
		if !IsExempted(v) {
			t.Errorf("%v should be exempted, but it isn't", v)
		}
	}

	other := "/accounts"

	if IsExempted(other) {
		t.Errorf("%v is exempted, but it shouldn't be")
	}
}

func TestExemptedGlob(t *testing.T) {
	//hand := New(nil)
	glob := "/[m-n]ail"

	ExemptedGlob(glob)

	test := "/mail"
	if !IsExempted(test) {
		t.Errorf("%v should be exempted, but it isn't.", test)
	}

	test = "/nail"
	if !IsExempted(test) {
		t.Errorf("%v should be exempted, but it isn't.", test)
	}

	test = "/snail"
	if IsExempted(test) {
		t.Errorf("%v should not be exempted, but it is.", test)
	}

	test = "/mail/outbox"
	if IsExempted(test) {
		t.Errorf("%v should not be exempted, but it is.", test)
	}
}

func TestExemptedGlobs(t *testing.T) {
	slice := []string{"/", "/accounts/*", "/post/?*"}
	matching := []string{"/", "/accounts/", "/accounts/johndoe", "/post/1", "/post/123"}

	nonMatching := []string{"", "/accounts",
		// Glob's * and ? don't match a forward slash.
		"/accounts/johndoe/posts",
		"/post/",
	}

	//hand := New(nil)
	ExemptedGlobs(slice...)

	for _, v := range matching {
		if !IsExempted(v) {
			t.Error("%v should be exempted, but it isn't.")
		}
	}

	for _, v := range nonMatching {
		if IsExempted(v) {
			t.Error("%v shouldn't be exempted, but it is")
		}
	}
}
