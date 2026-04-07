package reports

import (
	"testing"
	"time"
)

func TestParseTime_CustomFormat(t *testing.T) {
	input := "2024-06-15T10:30:00.123456Z"
	got, err := parseTime(input)
	if err != nil {
		t.Fatalf("parseTime(%q) error: %v", input, err)
	}
	want := time.Date(2024, 6, 15, 10, 30, 0, 123456000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseTime(%q) = %v, want %v", input, got, want)
	}
}

func TestParseTime_RFC3339(t *testing.T) {
	input := "2024-06-15T10:30:00Z"
	got, err := parseTime(input)
	if err != nil {
		t.Fatalf("parseTime(%q) error: %v", input, err)
	}
	want := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseTime(%q) = %v, want %v", input, got, want)
	}
}

func TestParseTime_RFC3339Nano(t *testing.T) {
	input := "2024-06-15T10:30:00.123456789Z"
	got, err := parseTime(input)
	if err != nil {
		t.Fatalf("parseTime(%q) error: %v", input, err)
	}
	want := time.Date(2024, 6, 15, 10, 30, 0, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseTime(%q) = %v, want %v", input, got, want)
	}
}

func TestParseTime_Invalid(t *testing.T) {
	_, err := parseTime("not-a-time")
	if err == nil {
		t.Error("expected error for invalid time string")
	}
}

func TestClientImplementsEventFetcher(t *testing.T) {
	var _ EventFetcher = (*Client)(nil)
}
