package zlicenser_server

import "testing"

func TestHelloWorld(t *testing.T) {
	got := HelloWorld()
	if got == "" {
		t.Fatal("HelloWorld returned empty string")
	}
	t.Logf("HelloWorld: %s", got)
}
