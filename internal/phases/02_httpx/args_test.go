package httpxprobe

import "testing"

func TestExtractField(t *testing.T) {
	line := `{"url":"https://example.com","status_code":200,"cdn":true,"title":"Home"}`
	if got := extractField(line, "\"url\":"); got != "https://example.com" {
		t.Errorf("url = %q, want https://example.com", got)
	}
	if got := extractField(line, "\"missing\":"); got != "" {
		t.Errorf("missing field should return empty, got %q", got)
	}
}

func TestDedupSort(t *testing.T) {
	in := []string{"b", "a", "b", "", "a", "c"}
	got := dedupSort(in)
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
}
