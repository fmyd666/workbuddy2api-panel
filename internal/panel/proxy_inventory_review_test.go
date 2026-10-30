package panel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/fmyd666/workbuddy2api-panel/internal/pool"
)

func TestProxyInventoryTestPersistenceFailureRestoresPreviousState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	dir := t.TempDir()
	p := New(Config{Pool: pool.New(""), ProxyFile: filepath.Join(dir, "proxies.json")})
	i := p.inventory()
	previous := &proxyTestResult{OK: false, LatencyMS: 987, CheckedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)}
	const id = "0123456789abcdef0123456789abcdef"
	i.items[id] = proxyEntry{ID: id, Name: "local test", Raw: "http://" + listener.Addr().String(), Type: "http", Selectable: true, LastTest: previous}
	// Point persistence at an existing directory: test dialing succeeds, atomic rename fails.
	i.path = dir

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/panel/api/proxies/"+id+"/test", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure, got %d: %s", rec.Code, rec.Body.String())
	}
	got := i.items[id].LastTest
	if got == nil || *got != *previous {
		t.Fatalf("failed persistence did not restore prior test result: got=%+v want=%+v", got, previous)
	}
}
