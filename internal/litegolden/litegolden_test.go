package litegolden

import "testing"

func TestGet(t *testing.T) {
	if len(Get("hello")) == 0 {
		t.Fatal("empty vector")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for a missing vector")
		}
	}()
	Get("missing")
}
