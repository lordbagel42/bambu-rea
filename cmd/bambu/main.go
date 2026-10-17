// Command bambu is a terminal replacement for the Bambu Handy app: it logs in
// to the Bambu cloud, lists and watches your printers, sends every printer
// command the app knows, and reaches any cloud endpoint, through the
// bambu-api HTTP contract (in-process by default, or a remote server).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

type app struct {
	cfg  *Config
	api  *apiClient
	json bool
	wait bool
	out  *os.File
	ctx  context.Context

	printerFlag string
}

type command struct {
	name, args, help string
	run              func(a *app, args []string) error
	needsAuth        bool
}

var commands = []command{
	{"login", "[email]", "Sign in to the Bambu cloud (password, email code and 2FA prompts)", (*app).cmdLogin, false},
	{"logout", "", "Invalidate the saved session", (*app).cmdLogout, true},
	{"whoami", "", "Show the signed-in account", (*app).cmdWhoami, true},
	{"printers", "", "List printers bound to the account and registered LAN printers", (*app).cmdPrinters, false},
	{"use", "<serial>", "Set the default printer", (*app).cmdUse, false},
	{"status", "[serial]", "Live status: state, progress, temperatures, fans, AMS, errors", (*app).cmdStatus, false},
	{"watch", "[serial]", "Follow status changes until Ctrl-C", (*app).cmdWatch, false},
	{"pause", "", "Pause the running print", (*app).cmdPause, false},
	{"resume", "", "Resume a paused print", (*app).cmdResume, false},
	{"stop", "", "Cancel the running print", (*app).cmdStop, false},
	{"speed", "<silent|standard|sport|ludicrous>", "Set the print speed profile", (*app).cmdSpeed, false},
	{"light", "<on|off> [node]", "Chamber light (or another led_node)", (*app).cmdLight, false},
	{"fan", "<part|aux|chamber|N> <0-100>", "Set a fan speed in percent", (*app).cmdFan, false},
	{"temp", "<nozzle|bed> <celsius> [extruder]", "Set a target temperature", (*app).cmdTemp, false},
	{"gcode", "<line>... | -", "Send raw G-code (from arguments or stdin)", (*app).cmdGcode, false},
	{"move", "[-x N] [-y N] [-z N] [-f feed]", "Relative jog, like the app's jog pad", (*app).cmdMove, false},
	{"home", "[x] [y] [z]", "Home all or selected axes", (*app).cmdHome, false},
	{"ams", "status | load <ams> <slot> | unload | drying ...", "AMS filament handling", (*app).cmdAMS, false},
	{"print", "<file on printer storage> [flags]", "Start printing a .gcode/.3mf already on the printer (gcode_file)", (*app).cmdPrint, false},
	{"skip", "<object id>...", "Skip objects in the running print", (*app).cmdSkip, false},
	{"calibrate", "[bed-leveling] [vibration] [motor-noise] [flow]", "Run printer calibration (option bitmask)", (*app).cmdCalibrate, false},
	{"cmd", "<Name> [key=value]... | --list", "Send any catalogued printer command", (*app).cmdCmd, false},
	{"raw", "<module> <command> [key=value]...", "Send an arbitrary MQTT envelope", (*app).cmdRaw, false},
	{"security", "[status|exchange|drop]", "MQTT secure channel (app-certificate exchange)", (*app).cmdSecurity, false},
	{"tasks", "[-n limit] [-all]", "Print history for the default printer (or all)", (*app).cmdTasks, true},
	{"cloud", "<GET|POST|PUT|DELETE> <service/path> [-d json|@file] [-q k=v]...", "Call any Bambu cloud endpoint with the app's headers", (*app).cmdCloud, true},
	{"endpoints", "[filter]", "List catalogued cloud endpoints", (*app).cmdEndpoints, false},
	{"appcert", "", "Show the IoT app certificate in use", (*app).cmdAppCert, false},
	{"lan", "add <ip> <serial> <access code> | list | rm <serial>", "LAN-mode printers (no cloud needed)", (*app).cmdLAN, false},
	{"config", "[key [value]]", "Show or set region, server, apiKey, printer", (*app).cmdConfig, false},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && len(ae.Detail) > 0 {
			fmt.Fprintf(os.Stderr, "bambu: %v\n%s\n", err, ae.Detail)
		} else {
			fmt.Fprintf(os.Stderr, "bambu: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("bambu", flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }
	a := &app{out: os.Stdout, wait: true}
	var server, apiKey string
	var timeout time.Duration
	fs.StringVar(&a.printerFlag, "p", "", "printer serial (default: `bambu use`, or the only printer)")
	fs.BoolVar(&a.json, "json", false, "print raw JSON instead of tables")
	fs.StringVar(&server, "server", os.Getenv("BAMBU_SERVER"), "remote bambu-api base URL (default: run in-process)")
	fs.StringVar(&apiKey, "api-key", os.Getenv("BAMBU_API_KEY"), "X-API-Key for a remote server")
	fs.DurationVar(&timeout, "timeout", 45*time.Second, "per-request timeout")
	noWait := fs.Bool("no-wait", false, "do not wait for the printer's acknowledgement")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	a.wait = !*noWait
	if fs.NArg() == 0 {
		usage(fs)
		return errors.New("command required")
	}
	name, args := fs.Arg(0), fs.Args()[1:]
	if name == "help" {
		usage(fs)
		return nil
	}
	var cmd *command
	for i := range commands {
		if commands[i].name == name {
			cmd = &commands[i]
		}
	}
	if cmd == nil {
		return fmt.Errorf("unknown command %q (try `bambu help`)", name)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	a.cfg = cfg
	if server == "" {
		server = cfg.Server
	}
	if apiKey == "" {
		apiKey = cfg.APIKey
	}
	if cmd.needsAuth && cfg.Token == "" {
		return errors.New("not signed in; run `bambu login`")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.ctx = ctx
	a.api, err = newAPIClient(cfg, server, apiKey, timeout)
	if err != nil {
		return err
	}
	defer a.api.close()
	return cmd.run(a, args)
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprintln(w, "usage: bambu [flags] <command> [args]")
	fmt.Fprintln(w, "\nflags:")
	fs.PrintDefaults()
	fmt.Fprintln(w, "\ncommands:")
	width := 0
	for _, c := range commands {
		if n := len(c.name) + 1 + len(c.args); n > width {
			width = n
		}
	}
	for _, c := range commands {
		fmt.Fprintf(w, "  %-*s  %s\n", width, strings.TrimSpace(c.name+" "+c.args), c.help)
	}
	fmt.Fprintln(w, "\nenvironment: BAMBU_CONFIG, BAMBU_SERVER, BAMBU_API_KEY")
}

// ------------------------------------------------------------------ helpers

// printer resolves the serial to act on: -p, else the saved default, else the
// single printer on the account.
func (a *app) printer() (string, error) {
	if a.printerFlag != "" {
		return a.printerFlag, nil
	}
	if a.cfg.Printer != "" {
		return a.cfg.Printer, nil
	}
	sns := []string{}
	for _, l := range a.cfg.LAN {
		sns = append(sns, l.Serial)
	}
	if a.cfg.Token != "" {
		devs, err := a.cloudDevices()
		if err == nil {
			for _, d := range devs {
				sns = append(sns, d.Serial)
			}
		}
	}
	switch len(sns) {
	case 0:
		return "", errors.New("no printer: sign in, add a LAN printer, or pass -p <serial>")
	case 1:
		return sns[0], nil
	default:
		sort.Strings(sns)
		return "", fmt.Errorf("several printers (%s); pick one with -p or `bambu use`", strings.Join(sns, ", "))
	}
}

// printerPath returns /v1/devices/<sn> after making sure a LAN printer is
// registered with the server (registration is per server process).
func (a *app) printerPath(sn string) (string, error) {
	if lp := a.cfg.lanPrinter(sn); lp != nil {
		if err := a.ensureLAN(lp); err != nil {
			return "", err
		}
	} else if a.cfg.Token == "" {
		return "", fmt.Errorf("%s is not a LAN printer and you are not signed in", sn)
	}
	return "/v1/devices/" + sn, nil
}

func (a *app) ensureLAN(lp *LANPrinter) error {
	var list []struct {
		Serial string `json:"serial"`
	}
	if err := a.api.do(a.ctx, "GET", "/v1/lan/devices", nil, nil, &list); err == nil {
		for _, l := range list {
			if l.Serial == lp.Serial {
				return nil
			}
		}
	}
	body := map[string]any{"ip": lp.IP, "serial": lp.Serial, "accessCode": lp.AccessCode, "name": lp.Name, "insecure": lp.Insecure}
	return a.api.do(a.ctx, "POST", "/v1/lan/devices", nil, body, nil)
}

// send posts a catalogued command and prints the acknowledgement.
func (a *app) send(name string, params map[string]any) error {
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	if params == nil {
		params = map[string]any{}
	}
	var res commandResult
	if err := a.api.do(a.ctx, "POST", base+"/commands/"+name, a.waitQuery(), params, &res); err != nil {
		return err
	}
	return a.printResult(&res)
}

// commandResult mirrors internal/api's response for a printer command.
type commandResult struct {
	SequenceID string         `json:"sequenceId"`
	Module     string         `json:"module"`
	Command    string         `json:"command"`
	Result     string         `json:"result,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Errno      int            `json:"errno,omitempty"`
	ErrCode    int            `json:"errCode,omitempty"`
	Reply      map[string]any `json:"reply,omitempty"`
	Sent       map[string]any `json:"sent"`
	Secured    bool           `json:"secured"`
}

func (a *app) printResult(res *commandResult) error {
	if a.json {
		return a.emit(res)
	}
	status := res.Result
	if status == "" {
		status = "sent"
	}
	line := fmt.Sprintf("%s/%s: %s", res.Module, res.Command, status)
	if res.Reason != "" {
		line += " (" + res.Reason + ")"
	}
	if res.Errno != 0 {
		line += fmt.Sprintf(" errno=%d", res.Errno)
	}
	if res.ErrCode != 0 {
		line += fmt.Sprintf(" err_code=0x%08x", res.ErrCode)
	}
	if res.Secured {
		line += " [signed]"
	}
	fmt.Fprintln(a.out, line)
	// Surface data-bearing replies (get_fan, get_access_code, ...) but not the
	// params real printers echo back.
	sent, _ := res.Sent[res.Module].(map[string]any)
	extra := map[string]any{}
	for k, v := range res.Reply {
		switch k {
		case "command", "sequence_id", "result", "reason", "errno", "err_code", "timestamp":
		default:
			if sv, echoed := sent[k]; echoed && fmt.Sprint(sv) == fmt.Sprint(v) {
				continue
			}
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		b, _ := json.MarshalIndent(extra, "", "  ")
		fmt.Fprintln(a.out, string(b))
	}
	if res.Result != "" && res.Result != "success" && res.Result != "SUCCESS" {
		return errors.New("printer rejected the command")
	}
	return nil
}

func (a *app) emit(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// kv parses key=value arguments into command params; values that parse as
// JSON (numbers, booleans, arrays, objects) keep their type.
func kv(args []string) (map[string]any, error) {
	out := map[string]any{}
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("expected key=value, got %q", arg)
		}
		var parsed any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			out[k] = parsed
		} else {
			out[k] = v
		}
	}
	return out, nil
}

// parseArgs parses flags that may appear before or after positional
// arguments (Go's flag package stops at the first positional) and returns the
// positionals in order.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
		if len(args) == 0 {
			return pos, nil
		}
	}
}
