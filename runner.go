package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var (
	vulnerabilityIDPattern = regexp.MustCompile(`^GO-\d{4}-\d+$`)
	vulnerabilityHeader    = regexp.MustCompile(`^Vulnerability #\d+:\s+(GO-\d{4}-\d+)\s*$`)
	summaryLine            = regexp.MustCompile(`^(Your code is affected by |This scan found |Use '-show )`)
)

type vulncheckRunner interface {
	Run(args ...string) (combined []byte, exitCode int, err error)
}

type commandRunner struct {
	path string
}

type findingFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

func (r commandRunner) Run(args ...string) (combined []byte, exitCode int, err error) {
	// The executable is selected by the caller through -govulncheck. This is the
	// intended command boundary of the wrapper rather than shell interpolation.
	cmd := exec.Command(r.path, args...) // #nosec G204
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	runErr := cmd.Run()
	if runErr == nil {
		return output.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return output.Bytes(), exitErr.ExitCode(), nil
	}
	return output.Bytes(), 2, runErr
}

func run(
	out io.Writer,
	errOut io.Writer,
	scanner vulncheckRunner,
	ignorePath string,
	showIgnored bool,
	scanArgs []string,
) int {
	ignored, err := loadIDs(ignorePath)
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: %v\n", err)
		return 2
	}

	jsonArgs := append([]string{"-format=json"}, scanArgs...)
	jsonOutput, exitCode, err := scanner.Run(jsonArgs...)
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: run govulncheck: %v\n", err)
		return 2
	}
	// Current govulncheck versions return zero for machine-readable output.
	// Exit code 3 is retained for compatibility with older releases.
	if exitCode != 0 && exitCode != 3 {
		_, _ = errOut.Write(jsonOutput)
		return exitCode
	}

	found, err := parseAffectedOSVIDsFromJSON(bytes.NewReader(jsonOutput))
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: parse govulncheck JSON: %v\n", err)
		return 2
	}

	unignored := unignoredIDs(found, ignored)
	if len(unignored) == 0 {
		return handleIgnoredFindings(out, errOut, scanner, showIgnored, scanArgs, found)
	}
	return handleUnignoredFindings(out, errOut, scanner, ignorePath, scanArgs, unignored)
}

func handleIgnoredFindings(
	out io.Writer,
	errOut io.Writer,
	scanner vulncheckRunner,
	showIgnored bool,
	scanArgs []string,
	found []string,
) int {
	if !showIgnored || len(found) == 0 {
		return 0
	}

	traceOutput, exitCode, err := scanner.Run(append([]string{"-show=traces"}, scanArgs...)...)
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: run govulncheck traces: %v\n", err)
		return 2
	}
	if exitCode != 0 && exitCode != 3 {
		_, _ = errOut.Write(traceOutput)
		return exitCode
	}
	printed, err := filterTraces(bytes.NewReader(traceOutput), out, idSet(found))
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: filter traces: %v\n", err)
		return 2
	}
	if !printed {
		fmt.Fprintln(errOut, "govulncheck-ignore: no traces matched; printing raw govulncheck output")
		_, _ = out.Write(traceOutput)
	}
	return 0
}

func handleUnignoredFindings(
	out io.Writer,
	errOut io.Writer,
	scanner vulncheckRunner,
	ignorePath string,
	scanArgs []string,
	unignored []string,
) int {
	fmt.Fprintf(
		errOut,
		"govulncheck: vulnerabilities not in %s: %s\n",
		ignorePath,
		strings.Join(unignored, ", "),
	)
	fmt.Fprintln(errOut, "govulncheck: unignored vulnerabilities found; rerunning with filtered traces...")

	traceOutput, exitCode, err := scanner.Run(append([]string{"-show=traces"}, scanArgs...)...)
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: run govulncheck traces: %v\n", err)
		return 2
	}
	if exitCode != 0 && exitCode != 3 {
		_, _ = errOut.Write(traceOutput)
		return exitCode
	}
	printed, err := filterTraces(bytes.NewReader(traceOutput), out, idSet(unignored))
	if err != nil {
		fmt.Fprintf(errOut, "govulncheck-ignore: filter traces: %v\n", err)
		return 2
	}
	if !printed {
		fmt.Fprintln(
			errOut,
			"govulncheck-ignore: no traces matched unignored vulnerabilities; the govulncheck text format may have changed",
		)
		_, _ = errOut.Write(traceOutput)
		return 2
	}
	return 1
}

func parseAffectedOSVIDsFromJSON(r io.Reader) ([]string, error) {
	type finding struct {
		OSV   string         `json:"osv"`
		Trace []findingFrame `json:"trace"`
	}

	scanLevel := "symbol"
	var findings []finding
	decoder := json.NewDecoder(r)
	for {
		var message struct {
			Config *struct {
				ScanLevel string `json:"scan_level"`
			} `json:"config"`
			Finding *finding `json:"finding"`
		}
		if err := decoder.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if message.Config != nil && message.Config.ScanLevel != "" {
			scanLevel = message.Config.ScanLevel
		}
		if message.Finding != nil {
			findings = append(findings, *message.Finding)
		}
	}

	if scanLevel != "module" && scanLevel != "package" && scanLevel != "symbol" {
		return nil, fmt.Errorf("unsupported govulncheck scan level %q", scanLevel)
	}

	seen := make(map[string]bool)
	var ids []string
	for _, finding := range findings {
		if finding.OSV == "" || seen[finding.OSV] || !findingMatchesScanLevel(finding.Trace, scanLevel) {
			continue
		}
		seen[finding.OSV] = true
		ids = append(ids, finding.OSV)
	}
	sort.Strings(ids)
	return ids, nil
}

func findingMatchesScanLevel(trace []findingFrame, scanLevel string) bool {
	for _, frame := range trace {
		switch scanLevel {
		case "symbol":
			if frame.Function != "" {
				return true
			}
		case "package":
			if frame.Package != "" {
				return true
			}
		case "module":
			if frame.Module != "" {
				return true
			}
		}
	}
	return false
}

func loadIDs(path string) (map[string]bool, error) {
	contents, err := os.ReadFile(path) // #nosec G304 -- -ignore intentionally selects a policy file.
	if err != nil {
		return nil, fmt.Errorf("open ignore file %s: %w", path, err)
	}

	ids := make(map[string]bool)
	for index, rawLine := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !vulnerabilityIDPattern.MatchString(line) {
			return nil, fmt.Errorf("%s:%d: invalid vulnerability ID %q", path, index+1, line)
		}
		ids[line] = true
	}
	return ids, nil
}

func unignoredIDs(found []string, ignored map[string]bool) []string {
	var ids []string
	for _, id := range found {
		if !ignored[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func idSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func filterTraces(in io.Reader, out io.Writer, ids map[string]bool) (printed bool, err error) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	writer := bufio.NewWriter(out)
	defer func() {
		if flushErr := writer.Flush(); flushErr != nil && err == nil {
			err = flushErr
		}
	}()

	var (
		block         []string
		include       bool
		printedHeader bool
	)

	flush := func() {
		if !include || len(block) == 0 {
			block = block[:0]
			return
		}
		if !printedHeader {
			fmt.Fprintln(writer, "=== Symbol Results ===")
			fmt.Fprintln(writer)
			printedHeader = true
		}
		for _, line := range block {
			fmt.Fprintln(writer, line)
		}
		fmt.Fprintln(writer)
		printed = true
		block = block[:0]
	}

	for scanner.Scan() {
		line := scanner.Text()
		if match := vulnerabilityHeader.FindStringSubmatch(line); match != nil {
			flush()
			include = ids[match[1]]
			block = append(block, line)
			continue
		}
		if len(block) == 0 {
			continue
		}
		if summaryLine.MatchString(line) {
			flush()
			include = false
			block = block[:0]
			continue
		}
		block = append(block, line)
	}
	if err := scanner.Err(); err != nil {
		return printed, err
	}
	flush()
	return printed, nil
}
