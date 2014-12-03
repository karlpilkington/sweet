package sweet

import (
	"fmt"
	"time"
)

type Cisco struct {
}

func newCiscoCollector() Collector {
	return Cisco{}
}

func (collector Cisco) Collect(device DeviceAccess) (map[string]string, error) {
	result := make(map[string]string)

	c, err := newSSHCollector(device)
	if err != nil {
		return result, err
	}

	if err := expect("assword:", c.Receive); err != nil {
		return result, err
	}
	c.Send <- device.Config["pass"] + "\n"
	multi := []string{"#", ">", "assword:"}
	m, err := expectMulti(multi, c.Receive)
	if err != nil {
		return result, err
	}
	if m == "assword:" { // bad pw
		return result, fmt.Errorf("%s: Bad login password.", device.Hostname)
	} else if m == ">" { // attempt enable
		c.Send <- "enable\n"
		if err := expect("assword:", c.Receive); err != nil {
			return result, err
		}
		c.Send <- device.Config["enable"] + "\n"
		if err := expect("#", c.Receive); err != nil {
			return result, err
		}
	}
	c.Send <- "terminal length 0\n"
	if err := expect("#", c.Receive); err != nil {
		return result, err
	}
	c.Send <- "terminal pager 0\n"
	if err := expect("#", c.Receive); err != nil {
		return result, err
	}
	c.Send <- "show running-config\n"
	result["config"], err = timeoutSave(c.Receive, 2*time.Second)
	if err != nil {
		return result, err
	}
	c.Send <- "exit\n"

	return result, nil
}
