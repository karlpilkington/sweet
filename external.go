package sweet

// sweet.go: network device backups and change alerts for the 21st century - inspired by RANCID.

import (
	"bytes"
	"fmt"
	"github.com/kballard/go-shellquote"
	"os"
	"os/exec"
	"strings"
	"time"
)

type External struct {
}

func newExternalCollector() Collector {
	return External{}
}

func (collector External) Collect(device DeviceAccess) (map[string]string, error) {
	var cmd *exec.Cmd
	result := make(map[string]string)

	commandParts, err := shellquote.Split(device.Config["scriptPath"])
	if err != nil {
		return result, err
	}
	if len(commandParts) > 1 {
		cmd = exec.Command(commandParts[0], commandParts[1:]...)
	} else {
		cmd = exec.Command(commandParts[0])
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return result, err
	}

	cmdDone := make(chan error)

	go func() {
		cmdDone <- cmd.Wait()
	}()

	select {
	case err := <-cmdDone:
		if err != nil {
			errMessage := strings.TrimRight(stderr.String(), "\n") + " " + err.Error()
			return result, fmt.Errorf("Error collecting from %s: %s", device.Hostname, errMessage)
		}
	case <-time.After(device.Timeout):
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return result, err
		}
		return result, fmt.Errorf("Timeout collecting from %s after %d seconds", device.Hostname, int(device.Timeout.Seconds()))
	}
	result["config"] = stdout.String()
	// TODO: cleanup external script output to not include SSH session junk
	return result, nil
}
