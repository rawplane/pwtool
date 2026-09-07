package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendDisabled(t *testing.T) {
	n := New("", false)
	n.Send(context.Background(), "should be a no-op")
}

func TestSendEmptyURL(t *testing.T) {
	n := New("", true)
	n.Send(context.Background(), "should be a no-op because URL is empty")
}

func TestSendSuccess(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		got <- string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(srv.URL, true)
	n.Send(context.Background(), "phase 1 done")
	select {
	case body := <-got:
		if body == "" {
			t.Fatal("webhook received empty body")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook did not receive a POST within timeout")
	}
}

func TestSendFailureIsSwallowed(t *testing.T) {
	// A server that returns 500 should not cause Send to panic or error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	n := New(srv.URL, true)
	n.Send(context.Background(), "this should be swallowed")
}

func TestSendUnreachableIsSwallowed(t *testing.T) {
	// Point at a closed port — Send must not panic or hang the pipeline.
	n := New("http://127.0.0.1:1/", true)
	n.Send(context.Background(), "unreachable test")
}

func TestJSONEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`back\slash`, `back\\slash`},
		{"newline\nhere", "newline\\nhere"},
	}
	for _, c := range cases {
		got := jsonEscape(c.in)
		if got != c.want {
			t.Errorf("jsonEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
