package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// cmdLogin runs the app's login state machine: password, then an emailed
// verification code when the server answers loginType=verifyCode, then a TOTP
// code when it answers loginType=tfa. Credentials are read from the terminal
// (password without echo) or from BAMBU_EMAIL / BAMBU_PASSWORD for scripts.
func (a *app) cmdLogin(args []string) error {
	email := os.Getenv("BAMBU_EMAIL")
	if len(args) > 0 {
		email = args[0]
	}
	if email == "" {
		email = a.cfg.Account
	}
	var err error
	if email == "" {
		if email, err = prompt("Email: "); err != nil {
			return err
		}
	}
	password := os.Getenv("BAMBU_PASSWORD")
	if password == "" {
		if password, err = promptSecret("Password: "); err != nil {
			return err
		}
	}
	res, err := a.login(cloud.LoginRequest{Account: email, Password: password})
	if err != nil {
		return err
	}
	for res.AccessToken == "" {
		switch res.LoginType {
		case cloud.LoginTypeVerifyCode:
			// Bambu emails a one-time code to new devices/locations.
			if err := a.api.do(a.ctx, "POST", "/v1/auth/email-code", nil, map[string]string{"email": email, "type": "codeLogin"}, nil); err != nil {
				return fmt.Errorf("request email code: %w", err)
			}
			code, err := prompt(fmt.Sprintf("Verification code sent to %s: ", email))
			if err != nil {
				return err
			}
			if res, err = a.login(cloud.LoginRequest{Account: email, Code: code}); err != nil {
				return err
			}
		case cloud.LoginTypeTFA:
			code, err := prompt("Two-factor code: ")
			if err != nil {
				return err
			}
			var out cloud.LoginResult
			if err := a.api.do(a.ctx, "POST", "/v1/auth/tfa", nil, map[string]string{"tfaKey": res.TfaKey, "tfaCode": code}, &out); err != nil {
				return err
			}
			res = &out
		default:
			msg := res.Message
			if msg == "" {
				msg = fmt.Sprintf("unexpected login response (loginType=%q)", res.LoginType)
			}
			return errors.New(msg)
		}
	}
	a.cfg.Account = email
	a.cfg.Token = res.AccessToken
	a.cfg.RefreshToken = res.RefreshToken
	a.api.token = res.AccessToken
	if err := a.cfg.save(); err != nil {
		return err
	}
	if a.json {
		return a.emit(map[string]any{"account": email, "expiresIn": res.ExpiresIn, "config": a.cfg.path})
	}
	fmt.Fprintf(a.out, "signed in as %s (session saved to %s)\n", email, a.cfg.path)
	if a.cfg.Printer == "" {
		if devs, err := a.cloudDevices(); err == nil && len(devs) == 1 {
			a.cfg.Printer = devs[0].Serial
			_ = a.cfg.save()
			fmt.Fprintf(a.out, "default printer: %s (%s)\n", devs[0].Name, devs[0].Serial)
		}
	}
	return nil
}

func (a *app) login(req cloud.LoginRequest) (*cloud.LoginResult, error) {
	var out cloud.LoginResult
	if err := a.api.do(a.ctx, "POST", "/v1/auth/login", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *app) cmdLogout([]string) error {
	err := a.api.do(a.ctx, "POST", "/v1/auth/logout", nil, nil, nil)
	a.cfg.Token, a.cfg.RefreshToken = "", ""
	if serr := a.cfg.save(); serr != nil {
		return serr
	}
	if err != nil {
		return fmt.Errorf("session cleared locally, but the cloud logout failed: %w", err)
	}
	fmt.Fprintln(a.out, "signed out")
	return nil
}

func (a *app) cmdWhoami([]string) error {
	var me map[string]any
	if err := a.api.do(a.ctx, "GET", "/v1/me", nil, nil, &me); err != nil {
		return err
	}
	if a.json {
		return a.emit(me)
	}
	tw := newTable(a.out)
	for _, k := range []string{"uid", "name", "account", "handle", "createTime"} {
		if v, ok := me[k]; ok && v != nil && v != "" {
			tw.row(k, fmt.Sprint(v))
		}
	}
	tw.flush()
	return nil
}

// device is the slice of the cloud's bind list the CLI needs.
type device struct {
	Serial  string `json:"dev_id"`
	Name    string `json:"name"`
	Online  bool   `json:"online"`
	Model   string `json:"dev_product_name"`
	Status  string `json:"print_status"`
	Access  string `json:"dev_access_code"`
	Nozzle  string `json:"nozzle_diameter"`
	ModelID string `json:"dev_model_name"`
}

func (a *app) cloudDevices() ([]device, error) {
	var out struct {
		Devices []device `json:"devices"`
	}
	if err := a.api.do(a.ctx, "GET", "/v1/devices", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Devices, nil
}

func (a *app) cmdPrinters([]string) error {
	type row struct {
		device
		Source  string `json:"source"`
		Default bool   `json:"default"`
	}
	var rows []row
	if a.cfg.Token != "" {
		devs, err := a.cloudDevices()
		if err != nil {
			return err
		}
		for _, d := range devs {
			rows = append(rows, row{device: d, Source: "cloud", Default: d.Serial == a.cfg.Printer})
		}
	}
	for _, l := range a.cfg.LAN {
		rows = append(rows, row{device: device{Serial: l.Serial, Name: l.Name, Access: l.AccessCode}, Source: "lan " + l.IP, Default: l.Serial == a.cfg.Printer})
	}
	if a.json {
		return a.emit(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.out, "no printers (sign in with `bambu login` or add one with `bambu lan add`)")
		return nil
	}
	tw := newTable(a.out)
	tw.row("", "SERIAL", "NAME", "MODEL", "ONLINE", "STATUS", "SOURCE")
	for _, r := range rows {
		mark := ""
		if r.Default {
			mark = "*"
		}
		online := "-"
		if r.Source == "cloud" {
			online = yesNo(r.Online)
		}
		tw.row(mark, r.Serial, r.Name, r.Model, online, r.Status, r.Source)
	}
	tw.flush()
	return nil
}

func (a *app) cmdUse(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: bambu use <serial>")
	}
	a.cfg.Printer = args[0]
	if err := a.cfg.save(); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "default printer: %s\n", args[0])
	return nil
}

func (a *app) cmdConfig(args []string) error {
	switch len(args) {
	case 0:
		view := map[string]any{"path": a.cfg.path, "region": a.cfg.Region, "account": a.cfg.Account, "signedIn": a.cfg.Token != "",
			"printer": a.cfg.Printer, "server": a.cfg.Server, "apiKey": a.cfg.APIKey != "", "hardwareId": a.cfg.HardwareID, "lan": len(a.cfg.LAN)}
		if a.json {
			return a.emit(view)
		}
		tw := newTable(a.out)
		for _, k := range []string{"path", "region", "account", "signedIn", "printer", "server", "apiKey", "hardwareId", "lan"} {
			tw.row(k, fmt.Sprint(view[k]))
		}
		tw.flush()
		return nil
	case 2:
		k, v := args[0], args[1]
		switch k {
		case "region":
			if _, ok := cloud.RegionByName(v); !ok {
				return fmt.Errorf("unknown region %q (intl|china)", v)
			}
			a.cfg.Region = v
		case "server":
			if v != "" {
				if _, err := url.ParseRequestURI(v); err != nil {
					return err
				}
			}
			a.cfg.Server = v
		case "apiKey":
			a.cfg.APIKey = v
		case "printer":
			a.cfg.Printer = v
		default:
			return fmt.Errorf("unknown key %q (region|server|apiKey|printer)", k)
		}
		return a.cfg.save()
	default:
		return errors.New("usage: bambu config [key value]")
	}
}

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// promptSecret reads without echo when stdin is a terminal and falls back to a
// plain line otherwise (pipes), so scripted use still works.
func promptSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return prompt(label)
	}
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
