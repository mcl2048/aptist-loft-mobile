package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run the actual command entrypoint in an isolated child test process, so its
// exit codes and bounded redaction are tested without replacing parser/network
// behavior or letting os.Exit terminate the parent suite.
func TestNodeProbeProcess(t *testing.T) {
	if os.Getenv("LOFT_NODEPROBE_TEST_CHILD") != "1" {
		return
	}
	os.Args = []string{"nodeprobe", "--nodes", os.Getenv("LOFT_NODEPROBE_TEST_FILE")}
	if mode := os.Getenv("LOFT_NODEPROBE_TEST_MODE"); mode != "" {
		os.Args = append(os.Args, "--mode", mode)
	}
	flag.CommandLine = flag.NewFlagSet("nodeprobe", flag.ExitOnError)
	main()
}

func probeProcess(t *testing.T, path string) (int, string) {
	return probeProcessMode(t, path, "")
}

func probeProcessMode(t *testing.T, path, mode string) (int, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestNodeProbeProcess$")
	command.Env = append(os.Environ(), "LOFT_NODEPROBE_TEST_CHILD=1", "LOFT_NODEPROBE_TEST_FILE="+path, "LOFT_NODEPROBE_TEST_MODE="+mode)
	output, err := command.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var status *exec.ExitError
	if !errors.As(err, &status) {
		t.Fatal(err)
	}
	return status.ExitCode(), string(output)
}

func TestLiteralHTTPSModeIsExplicitAndUnknownModesAreRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-private-input.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	status, output := probeProcessMode(t, path, "literal-https")
	if status == 0 || !strings.Contains(output, "no matching nodes in private input") {
		t.Fatal("explicit literal HTTPS mode was not recognized as a bounded probe mode")
	}
	status, output = probeProcessMode(t, path, "synthetic-private-mode")
	if status == 0 || !strings.Contains(output, "unsupported probe mode") || strings.Contains(output, "synthetic-private-mode") {
		t.Fatal("unknown probe mode was accepted or copied into a diagnostic")
	}
}

func TestEmptyOrUnrecognizedPrivateInputCannotReportProbeSuccess(t *testing.T) {
	for _, test := range []struct{ name, input string }{{"empty", ""}, {"no_nodes", "A private input header\nunsupported://synthetic-node\n"}} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-input.txt")
			if err := os.WriteFile(path, []byte(test.input), 0600); err != nil {
				t.Fatal(err)
			}
			status, _ := probeProcess(t, path)
			if status == 0 {
				t.Fatal("input containing no node reported a successful protocol probe")
			}
		})
	}
}

func TestOverallPrivateFileLimitRejectsMultilineInputInsteadOfTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-private-input.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("unrecognized synthetic input\n", 40000)), 0600); err != nil {
		t.Fatal(err)
	}
	status, output := probeProcess(t, path)
	if status == 0 || !strings.Contains(output, "private input exceeds byte limit") {
		t.Fatal("overall oversized file was silently truncated or misclassified")
	}
}

func TestPrivateInputErrorsCannotPrintPathCredentialsOrURIs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-private-marker.txt")
	_, output := probeProcess(t, path)
	if strings.Contains(output, "synthetic-private-marker") || strings.Contains(output, path) {
		t.Fatal("unavailable private input leaked its path")
	}
	if err := os.WriteFile(path, []byte("socks5://synthetic-user:synthetic-private-password@private-synthetic.test:0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	status, output := probeProcess(t, path)
	if status == 0 || strings.Contains(output, "synthetic-private-password") || strings.Contains(output, "private-synthetic.test") || strings.Contains(output, "socks5://") {
		t.Fatal("invalid private node succeeded or copied private input to output")
	}
}

func TestDiagnosticUnwrapsCauseWithoutCopyingPrivateErrorText(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{{"wrapped_eof", fmt.Errorf("synthetic-private-text: %w", stage("tcp_read_length", fmt.Errorf("synthetic-private-text: %w", io.EOF))), "tcp_read_length:eof"}, {"wrapped_short_read", stage("tcp_read_body", fmt.Errorf("synthetic-private-text: %w", io.ErrUnexpectedEOF)), "tcp_read_body:unexpected_eof"}, {"rejected", errors.New("synthetic-private-text"), "operation:rejected"}} {
		t.Run(test.name, func(t *testing.T) {
			if got := diagnostic(test.err); got != test.want {
				t.Fatalf("redacted diagnostic=%q want=%q", got, test.want)
			}
		})
	}
}
