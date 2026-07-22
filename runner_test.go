package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type stubResponse struct {
	output   string
	exitCode int
	err      error
}

type stubRunner struct {
	responses []stubResponse
	calls     [][]string
}

func (s *stubRunner) Run(args ...string) ([]byte, int, error) {
	s.calls = append(s.calls, append([]string(nil), args...))
	if len(s.responses) == 0 {
		return nil, 2, errors.New("unexpected call")
	}
	response := s.responses[0]
	s.responses = s.responses[1:]
	return []byte(response.output), response.exitCode, response.err
}

func TestLoadIDs(t *testing.T) {
	path := writeIgnoreFile(t, `
# reviewed in SECURITY.md
GO-2026-4349

GO-2026-4348
GO-2026-4349
`)
	ids, err := loadIDs(path)
	if err != nil {
		t.Fatalf("loadIDs: %v", err)
	}
	want := map[string]bool{"GO-2026-4348": true, "GO-2026-4349": true}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids=%v, want %v", ids, want)
	}
}

func TestLoadIDsRejectsInvalidEntry(t *testing.T) {
	path := writeIgnoreFile(t, "CVE-2026-1234\n")
	_, err := loadIDs(path)
	if err == nil || !strings.Contains(err.Error(), ":1: invalid vulnerability ID") {
		t.Fatalf("err=%v, want line-specific validation error", err)
	}
}

func TestParseAffectedOSVIDsFromJSON(t *testing.T) {
	input := strings.NewReader(`{"config":{"scan_level":"symbol"}}
{"finding":{"osv":"GO-2026-4349","trace":[{"module":"example.com/dependency"}]}}
{"finding":{"osv":"GO-2026-4349","trace":[{"module":"example.com/dependency","package":"example.com/dependency/pkg"}]}}
{"finding":{"osv":"GO-2026-4349","trace":[{"module":"example.com/dependency","package":"example.com/dependency/pkg","function":"Vulnerable"}]}}
{"finding":{"osv":"GO-2026-4349","trace":[{"module":"example.com/dependency","package":"example.com/dependency/pkg","function":"Vulnerable"}]}}
{"finding":{"osv":"GO-2026-4348","trace":[{"module":"stdlib","package":"os","function":"Affected"}]}}`)
	ids, err := parseAffectedOSVIDsFromJSON(input)
	if err != nil {
		t.Fatalf("parseAffectedOSVIDsFromJSON: %v", err)
	}
	if got := strings.Join(ids, ","); got != "GO-2026-4348,GO-2026-4349" {
		t.Fatalf("ids=%v", ids)
	}
}

func TestParseAffectedOSVIDsFromJSONHonorsPackageScanLevel(t *testing.T) {
	input := strings.NewReader(`{"config":{"scan_level":"package"}}
{"finding":{"osv":"GO-2026-4349","trace":[{"module":"example.com/dependency"}]}}
{"finding":{"osv":"GO-2026-4348","trace":[{"module":"example.com/dependency","package":"example.com/dependency/pkg"}]}}`)
	ids, err := parseAffectedOSVIDsFromJSON(input)
	if err != nil {
		t.Fatalf("parseAffectedOSVIDsFromJSON: %v", err)
	}
	if got := strings.Join(ids, ","); got != "GO-2026-4348" {
		t.Fatalf("ids=%v", ids)
	}
}

func TestRunFiltersTracesToUnignoredFindings(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "GO-2026-4349\n")
	scanner := &stubRunner{responses: []stubResponse{
		{output: findingsJSON("GO-2026-4348", "GO-2026-4349")},
		{output: traceOutput()},
	}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 1 {
		t.Fatalf("code=%d; stderr=%q; stdout=%q", code, errOut.String(), out.String())
	}
	if !strings.Contains(errOut.String(), "GO-2026-4348") {
		t.Fatalf("expected unignored summary, got %q", errOut.String())
	}
	if strings.Contains(out.String(), "GO-2026-4349") {
		t.Fatalf("stdout includes ignored finding: %q", out.String())
	}
	if !strings.Contains(out.String(), "GO-2026-4348") {
		t.Fatalf("stdout omits unignored finding: %q", out.String())
	}
	if strings.Contains(out.String(), "Your code is affected by") {
		t.Fatalf("stdout includes summary: %q", out.String())
	}
	wantCalls := [][]string{{"-format=json", "./..."}, {"-show=traces", "./..."}}
	if !reflect.DeepEqual(scanner.calls, wantCalls) {
		t.Fatalf("calls=%v, want %v", scanner.calls, wantCalls)
	}
}

func TestRunReturnsSuccessWhenAllFindingsAreIgnored(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "GO-2026-4349\n")
	scanner := &stubRunner{responses: []stubResponse{{output: findingsJSON("GO-2026-4349")}}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d; stderr=%q; stdout=%q", code, errOut.String(), out.String())
	}
	if len(scanner.calls) != 1 {
		t.Fatalf("calls=%v, expected JSON scan only", scanner.calls)
	}
}

func TestRunCanShowIgnoredFindingsWithoutFailing(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "GO-2026-4349\n")
	scanner := &stubRunner{responses: []stubResponse{
		{output: findingsJSON("GO-2026-4349")},
		{output: traceOutput()},
	}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, true, []string{"./..."})
	if code != 0 {
		t.Fatalf("code=%d; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "GO-2026-4349") || strings.Contains(out.String(), "GO-2026-4348") {
		t.Fatalf("unexpected stdout: %q", out.String())
	}
}

func TestRunRejectsMalformedJSON(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "")
	scanner := &stubRunner{responses: []stubResponse{{output: "{not-json"}}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 2 || !strings.Contains(errOut.String(), "parse govulncheck JSON") {
		t.Fatalf("code=%d; stderr=%q", code, errOut.String())
	}
}

func TestRunPreservesUnexpectedGovulncheckExit(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "")
	scanner := &stubRunner{responses: []stubResponse{{output: "compile failed\n", exitCode: 5}}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 5 || errOut.String() != "compile failed\n" {
		t.Fatalf("code=%d; stderr=%q", code, errOut.String())
	}
}

func TestRunFailsClosedWhenTraceFormatChanges(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "")
	scanner := &stubRunner{responses: []stubResponse{
		{output: findingsJSON("GO-2026-4348")},
		{output: "a new trace format\n"},
	}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 2 || !strings.Contains(errOut.String(), "text format may have changed") {
		t.Fatalf("code=%d; stderr=%q", code, errOut.String())
	}
}

func TestRunReportsExecutionFailure(t *testing.T) {
	ignorePath := writeIgnoreFile(t, "")
	scanner := &stubRunner{responses: []stubResponse{{err: errors.New("executable not found")}}}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(&out, &errOut, scanner, ignorePath, false, []string{"./..."})
	if code != 2 || !strings.Contains(errOut.String(), "executable not found") {
		t.Fatalf("code=%d; stderr=%q", code, errOut.String())
	}
}

func writeIgnoreFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".govulnignore")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}
	return path
}

func findingsJSON(ids ...string) string {
	var output strings.Builder
	for _, id := range ids {
		output.WriteString(`{"finding":{"osv":"`)
		output.WriteString(id)
		output.WriteString(`","trace":[{"module":"example.com/dependency","package":"example.com/dependency/pkg","function":"Vulnerable"}]}}`)
		output.WriteByte('\n')
	}
	return output.String()
}

func traceOutput() string {
	return `=== Symbol Results ===

Vulnerability #1: GO-2026-4348
  Unignored block

Vulnerability #2: GO-2026-4349
  Ignored block

Your code is affected by 2 vulnerabilities from 1 module.
`
}
