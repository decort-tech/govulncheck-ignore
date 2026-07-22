package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var version = "dev"

type cliOptions struct {
	govulncheckPath string
	ignorePath      string
	showIgnored     bool
	showVersion     bool
	scanArgs        []string
}

func main() {
	opts, err := parseCLI(os.Args[1:], os.Stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "govulncheck-ignore: %v\n", err)
		}
		os.Exit(2)
	}
	if opts.showVersion {
		fmt.Printf("govulncheck-ignore %s\n", version)
		return
	}

	code := run(
		os.Stdout,
		os.Stderr,
		commandRunner{path: opts.govulncheckPath},
		opts.ignorePath,
		opts.showIgnored,
		opts.scanArgs,
	)
	os.Exit(code)
}

func parseCLI(args []string, errOut io.Writer) (cliOptions, error) {
	opts := cliOptions{}
	flags := flag.NewFlagSet("govulncheck-ignore", flag.ContinueOnError)
	flags.SetOutput(errOut)
	flags.StringVar(&opts.govulncheckPath, "govulncheck", "govulncheck", "path to the govulncheck binary")
	flags.StringVar(&opts.ignorePath, "ignore", ".govulnignore", "ignore file containing one GO vulnerability ID per line")
	flags.BoolVar(&opts.showIgnored, "show-ignored", false, "print traces for ignored findings when no unignored findings remain")
	flags.BoolVar(&opts.showVersion, "version", false, "print version information")
	flags.Usage = func() {
		fmt.Fprintln(errOut, "Usage: govulncheck-ignore [options] [--] [govulncheck scan arguments]")
		fmt.Fprintln(errOut)
		fmt.Fprintln(errOut, "Options:")
		flags.PrintDefaults()
		fmt.Fprintln(errOut)
		fmt.Fprintln(errOut, "Pass govulncheck flags after --, for example:")
		fmt.Fprintln(errOut, "  govulncheck-ignore -- -tags=integration ./...")
	}

	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	opts.scanArgs = flags.Args()
	if len(opts.scanArgs) == 0 {
		opts.scanArgs = []string{"./..."}
	}
	if opts.showVersion {
		return opts, nil
	}
	if strings.TrimSpace(opts.govulncheckPath) == "" {
		return opts, errors.New("-govulncheck must not be empty")
	}
	if strings.TrimSpace(opts.ignorePath) == "" {
		return opts, errors.New("-ignore must not be empty")
	}
	if err := validateScanArgs(opts.scanArgs); err != nil {
		return opts, err
	}
	return opts, nil
}

func validateScanArgs(args []string) error {
	for _, arg := range args {
		name := arg
		if before, _, found := strings.Cut(name, "="); found {
			name = before
		}
		switch name {
		case "-format", "--format", "-json", "--json", "-show", "--show", "-version", "--version":
			return fmt.Errorf("govulncheck output flag %q is controlled by govulncheck-ignore", name)
		}
	}
	return nil
}
