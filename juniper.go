package sweet

import (
	"fmt"
	"time"
)

type JunOS struct {
}

func newJunOSCollector() Collector {
	return JunOS{}
}

func (collector JunOS) Collect(device DeviceAccess) (map[string]string, error) {
	result := make(map[string]string)

	c, err := newSSHCollector(device)
	if err != nil {
		return result, err
	}

	if err := expect("assword:", c.Receive); err != nil {
		return result, err
	}
	c.Send <- device.Config["pass"] + "\n"
	multi := []string{">", "assword:"}
	m, err := expectMulti(multi, c.Receive)
	if err != nil {
		return result, err
	}
	if m == "assword:" { // bad pw
		return result, fmt.Errorf("%s: Bad login password.", device.Hostname)
	}
	c.Send <- "set cli screen-length 0\n"
	if err := expect(">", c.Receive); err != nil {
		result["err"] = fmt.Sprintf("%s: %s", device.Hostname, err.Error())
		return result, err
	}
	c.Send <- "show configuration\n"
	result["config"], err = timeoutSave(c.Receive, 2500*time.Millisecond)
	if err != nil {
		result["err"] = fmt.Sprintf("%s: %s", device.Hostname, err.Error())
		return result, err
	}
	c.Send <- "exit\n"

	return result, nil
}
