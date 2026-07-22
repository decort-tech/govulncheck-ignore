package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseCLIUsesDefaultPattern(t *testing.T) {
	opts, err := parseCLI(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLI: %v", err)
	}
	if got := strings.Join(opts.scanArgs, " "); got != "./..." {
		t.Fatalf("scanArgs=%q, want ./...", got)
	}
}

func TestParseCLIForwardsScanArgumentsAfterDelimiter(t *testing.T) {
	opts, err := parseCLI([]string{"-ignore", "reviewed.txt", "--", "-tags=integration", "./cmd/..."}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLI: %v", err)
	}
	if opts.ignorePath != "reviewed.txt" {
		t.Fatalf("ignorePath=%q", opts.ignorePath)
	}
	if got := strings.Join(opts.scanArgs, " "); got != "-tags=integration ./cmd/..." {
		t.Fatalf("scanArgs=%q", got)
	}
}

func TestParseCLIRejectsControlledOutputFlags(t *testing.T) {
	_, err := parseCLI([]string{"--", "-format=sarif", "./..."}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "controlled") {
		t.Fatalf("err=%v, want controlled-output error", err)
	}
}

func TestParseCLIHelp(t *testing.T) {
	_, err := parseCLI([]string{"-h"}, &bytes.Buffer{})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err=%v, want flag.ErrHelp", err)
	}
}
