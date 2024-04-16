package main

import (
	"errors"
	"testing"
)

func TestVerifyLogic(t *testing.T) {
	data := []struct {
		in   string
		want bool
	}{
		{"./json/test1.json", false},
		{"./json/test2.json", true},
		{"./json/test3.json", false},
		{"./json/test4.json", false},
		{"./json/test5.json", true},
		{"./json/test6.json", false},
		{"./json/test7.json", true},
	}

	for _, d := range data {
		got, err := Verify(d.in)
		if err != nil {
			t.Error(err)
		} else if got != d.want {
			t.Errorf("JSONValidator(%#v) == %#v want %#v", d.in, got, d.want)
		}
	}
}

func TestVerifyErrors(t *testing.T) {
	data := []struct {
		in   string
		want error
	}{
		{"./json/test8.json", errors.New("value Sid has to be string but is <nil>")},
		{"./json/test9.json", errors.New("invalid JSON")},
		{"./json/test10.json", errors.New("accepted effects are: Allow and Deny but all was given")},
		{"./json/test11.json", errors.New("accepted versions are: 2012-10-17 and 2008-10-17 but 2012-10-16 was given")},
		{"./json/test12.json", errors.New("PolicyName length has to be between 1 and 128 but is 0")},
		{"./json/test13.json", errors.New("PolicyName doesn't match wanted format: `[\\w+=,.@-]+`")},
	}
	for _, d := range data {
		_, err := Verify(d.in)
		if errors.Is(err, d.want) {
			t.Errorf("Expected error: %s, but got: %s", d.want, err)
		}
	}
}
