package main

import "testing"

func TestJSONValidator(t *testing.T) {
	data := []struct {
		in   string
		want bool
	}{
		{"./json/test1.json", false},
		{"./json/test2.json", true},
		{"./json/test3.json", true},
		{"./json/test5.json", true},
		{"./json/test4.json", true},
	}

	for _, d := range data {
		if got := JSONValidator(d.in); got != d.want {
			t.Errorf("JSONValidator(%#v) == %#v want %#v", d.in, got, d.want)
		}
	}
}
