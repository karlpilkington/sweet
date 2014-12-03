package sweet

// sweet.go: network device backups and change alerts for the 21st century - inspired by RANCID.

import (
	"fmt"
	"github.com/kr/pty"
	"io"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/exec"
	"sync"
	"time"
)

const (
	recentHours = 12
)

// DeviceAccess stores host access info
type DeviceAccess struct {
	Hostname string
	Method   string
	Target   string
	Timeout  time.Duration
	Config   map[string]string
}

// Report is based on Git data for web or email interface.
type Report struct {
	Device        DeviceAccess
	Error         error
	Diff          string
	StatusMessage string
	Added         string
	Removed       string
	CollectedTime time.Time
	ChangedTime   time.Time
	Web           ReportWebData
}

// ReportWebData options for formatting web status page.
type ReportWebData struct {
	Class          string
	CSSID          string
	EnableDiffLink bool
	EnableConfLink bool
}

type SSHCollector struct {
	Receive chan string
	Send    chan string
}

type SweetOptions struct {
	Interval      time.Duration
	Timeout       time.Duration
	GitPush       bool
	Insecure      bool
	Concurrency   int
	HttpListen    string
	HttpEnabled   bool
	SmtpString    string
	Workspace     string
	ExecutableDir string
	ToEmail       string
	FromEmail     string
	UseSyslog     bool
	DefaultUser   string
	DefaultPass   string
	DefaultMethod string
	Syslog        *syslog.Writer
	Devices       []DeviceAccess
	Status        *Status
}

type Collector interface {
	Collect(device DeviceAccess) (map[string]string, error)
}

//// Kickoff collector runs
func RunCollectors(Opts *SweetOptions) {
	collectorSlots := make(chan bool, Opts.Concurrency)
	for {
		Opts.LogInfo(fmt.Sprintf("Starting %d collectors. [concurrency=%d]", len(Opts.Devices), Opts.Concurrency))
		done := make(chan string, len(Opts.Devices))

		go func() {
			for _, device := range Opts.Devices {
				collectorSlots <- true
				go collectDevice(device, Opts, done)
				//opts.logInfo(fmt.Sprintf("Collector started:  %s", device.Hostname))
			}
		}()
		Opts.LogInfo(fmt.Sprintf("Waiting for %d collectors.", len(Opts.Devices)))
		for i := 0; i < len(Opts.Devices); i++ {
			_ = <-collectorSlots
			doneHostname := <-done
			_ = doneHostname
			//opts.logInfo(fmt.Sprintf("Collector returned: %s", doneHostname))
		}
		Opts.LogInfo(fmt.Sprintf("Finished with all %d collectors.", len(Opts.Devices)))

		statusText, err := exec.Command("git", "status", "-s").Output()
		if err != nil {
			Opts.LogFatal(fmt.Sprintf("Git status error: %s", err.Error()))
		}
		if len(statusText) > 0 {
			_, err = exec.Command("git", "add", ".").Output()
			if err != nil {
				Opts.LogFatal(fmt.Sprintf("Git add error: %s", err.Error()))
			}

			commitMsg := "Sweet commit:\n" + string(statusText)
			_, err = exec.Command("git", "commit", "-a", "-m", commitMsg).Output()
			if err != nil {
				Opts.LogFatal(fmt.Sprintf("Git commit error: %s", err.Error()))
			}
			if Opts.GitPush == true {
				_, err = exec.Command("git", "push").Output()
				if err != nil {
					Opts.LogErr(fmt.Sprintf("Git push failed, continuing anyway: %s", err.Error()))
				}
			}

			go runReporter(*Opts)
			Opts.LogInfo(fmt.Sprintf("Committed changes to git."))
		} else {
			Opts.LogInfo(fmt.Sprintf("No changes detected."))
		}

		if Opts.Interval == 0 {
			Opts.LogInfo("Interval set to 0 - exiting.")
			os.Exit(0)
		}
		time.Sleep(Opts.Interval) // TODO time from start not end of collection
	}
}

//// Get and save config from a single device
func collectDevice(device DeviceAccess, Opts *SweetOptions, done chan string) {
	var err error

	if len(device.Method) == 0 {
		if len(Opts.DefaultMethod) == 0 {
			Opts.LogFatal(fmt.Sprintf("No method specified for %s and default-method not defined.", device.Hostname))
		}
		device.Method = Opts.DefaultMethod
	}

	// override timeouts in device configs
	device.Timeout = Opts.Timeout
	_, ok := device.Config["timeout"]
	if ok {
		device.Timeout, err = time.ParseDuration(device.Config["timeout"] + "s")
		if err != nil {
			Opts.LogFatal(fmt.Sprintf("Bad timeout setting %s for host %s", device.Config["timeout"], device.Hostname))
		}
	}
	// setup collection options
	_, ok = device.Config["user"]
	if !ok {
		if len(Opts.DefaultUser) == 0 {
			Opts.LogFatal(fmt.Sprintf("No user specified for %s and default-user not defined.", device.Hostname))
		}
		device.Config["user"] = Opts.DefaultUser
	}
	_, ok = device.Config["pass"]
	if !ok {
		if len(Opts.DefaultPass) == 0 {
			Opts.LogFatal(fmt.Sprintf("No pass specified for %s and default-pass not defined.", device.Hostname))
		}
		device.Config["pass"] = Opts.DefaultPass
	}
	_, ok = device.Config["enable"]
	if !ok {
		device.Config["enable"] = device.Config["pass"]
	}
	device.Target = device.Hostname
	_, ok = device.Config["ip"]
	if ok {
		device.Target = device.Config["ip"]
	}
	if Opts.Insecure {
		device.Config["insecure"] = "true"
	}

	rawConfig := ""
	status := DeviceStatus{}
	status.Hostname = device.Hostname

	var c Collector
	if device.Method == "external" {
		// handle absolute and relative script paths
		device.Config["scriptPath"] = device.Config["script"]
		if device.Config["script"][0] != os.PathSeparator {
			device.Config["scriptPath"] = Opts.ExecutableDir + string(os.PathSeparator) + device.Config["script"]
		}
		c = newExternalCollector()
	} else if device.Method == "cisco" {
		c = newCiscoCollector()
	} else if device.Method == "junos" {
		c = newJunOSCollector()
	} else {
		status.Message = fmt.Sprintf("Unknown access method: %s", device.Method)
		Opts.LogErr(status.Message)
		Opts.Status.Set(status)
		done <- device.Hostname
		return
	}

	collectionResults := make(map[string]string)
	r := make(chan map[string]string)
	e := make(chan error)
	go func() {
		result, err := c.Collect(device)
		if err != nil {
			e <- err
		} else {
			r <- result
		}
	}()
	select {
	case collectionResults = <-r:
	case <-time.After(Opts.Timeout):
		status.Message = fmt.Sprintf("Timeout collecting from %s after %d seconds", device.Hostname, int(device.Timeout.Seconds()))
		Opts.LogErr(status.Message)
		Opts.Status.Set(status)
		done <- device.Hostname
		return
	case err := <-e:
		Opts.LogErr(err.Error())
		status.Message = err.Error()
		Opts.Status.Set(status)
		done <- device.Hostname
		return
	}
	// TODO for now we only handle config collectionResults
	rawConfig, ok = collectionResults["config"]
	if !ok {
		status.Message = fmt.Sprintf("Config missing from collection results", device.Hostname)
		Opts.LogErr(status.Message)
		Opts.Status.Set(status)
		done <- device.Hostname
		return
	}

	// save the config to the workspace
	// TODO save out non-config data
	err = ioutil.WriteFile(device.Hostname, []byte(rawConfig), 0644)
	if err != nil {
		Opts.LogFatal(fmt.Sprintf("Error saving config to workspace: %s", err.Error()))
	}

	// notify RunCollectors() that we're done
	status.Message = "success"
	status.LastSuccess = time.Now()
	Opts.Status.Set(status)
	done <- device.Hostname
}

func newSSHCollector(device DeviceAccess) (*SSHCollector, error) {
	c := new(SSHCollector)
	c.Receive = make(chan string)
	c.Send = make(chan string)

	var cmd *exec.Cmd
	_, ok := device.Config["insecure"]
	if ok && device.Config["insecure"] == "true" {
		cmd = exec.Command("ssh", "-oStrictHostKeyChecking=no", device.Config["user"]+"@"+device.Target)
	} else {
		cmd = exec.Command("ssh", device.Config["user"]+"@"+device.Target)
	}

	f, err := pty.Start(cmd)
	if err != nil {
		return c, err
	}

	go func() {
		for {
			str, err := readChunk(f)
			if err != nil {
				close(c.Receive)
				return
			}
			c.Receive <- str
		}
	}()

	go func() {
		for {
			select {
			case command, exists := <-c.Send:
				{
					if !exists {
						return
					}
					_, err := io.WriteString(f, command)
					if err != nil {
						panic("send error")
					}
				}
			}
		}
	}()

	return c, nil
}

type Status struct {
	Status map[string]DeviceStatus
	Lock   sync.Mutex
}
type DeviceStatus struct {
	Hostname    string
	Message     string
	LastSuccess time.Time
}

func (s *Status) Get(device string) DeviceStatus {
	defer func() {
		s.Lock.Unlock()
	}()
	s.Lock.Lock()
	return s.Status[device]
}
func (s *Status) GetAll(device string) map[string]DeviceStatus {
	defer func() {
		s.Lock.Unlock()
	}()
	s.Lock.Lock()
	return s.Status
}

func (s *Status) Set(stat DeviceStatus) {
	defer func() {
		s.Lock.Unlock()
	}()
	s.Lock.Lock()
	s.Status[stat.Hostname] = stat
}
