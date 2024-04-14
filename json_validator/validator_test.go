package main

import "testing"

func TestVerify(t *testing.T) {
	data := []struct {
		in   string
		want bool
	}{
		{"./json/test1.json", false},
		{"./json/test2.json", true},
		{"./json/test3.json", true},
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
