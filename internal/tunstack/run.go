package tunstack

import (
	"fmt"
	"os/exec"
	"strings"
)

// run runs a system command, returning its output in the error.
func run(args ...string) error {
	_, err := output(args...)
	return err
}

func output(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
