package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

func (a *app) cmdTasks(args []string) error {
	fs := flag.NewFlagSet("tasks", flag.ContinueOnError)
	limit := fs.Int("n", 20, "number of tasks")
	all := fs.Bool("all", false, "all printers, not only the default one")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	q := url.Values{"limit": {strconv.Itoa(*limit)}, "offset": {"0"}}
	if !*all {
		if sn, err := a.printer(); err == nil {
			q.Set("deviceId", sn)
		}
	}
	var out struct {
		Total int `json:"total"`
		Hits  []struct {
			ID         int64  `json:"id"`
			Title      string `json:"title"`
			DeviceName string `json:"deviceName"`
			DeviceID   string `json:"deviceId"`
			Status     int    `json:"status"`
			StartTime  string `json:"startTime"`
			EndTime    string `json:"endTime"`
			CostTime   int64  `json:"costTime"`
			Weight     any    `json:"weight"`
			Length     any    `json:"length"`
		} `json:"hits"`
	}
	var raw json.RawMessage
	if err := a.api.do(a.ctx, "GET", "/v1/cloud/user-service/my/tasks", q, nil, &raw); err != nil {
		return err
	}
	if a.json {
		fmt.Fprintln(a.out, string(raw))
		return nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	tw := newTable(a.out)
	tw.row("ID", "STARTED", "DURATION", "STATUS", "PRINTER", "TITLE")
	for _, h := range out.Hits {
		started := h.StartTime
		if t, err := time.Parse(time.RFC3339, h.StartTime); err == nil {
			started = t.Local().Format("2006-01-02 15:04")
		}
		tw.row(strconv.FormatInt(h.ID, 10), started, minutes(float64(h.CostTime)/60), taskStatus(h.Status), h.DeviceName, h.Title)
	}
	tw.flush()
	if out.Total > len(out.Hits) {
		fmt.Fprintf(a.out, "(%d of %d; use -n)\n", len(out.Hits), out.Total)
	}
	return nil
}

// taskStatus maps user-service task status codes (the app's TaskStatus enum).
func taskStatus(s int) string {
	switch s {
	case 1:
		return "printing"
	case 2:
		return "finished"
	case 3:
		return "failed"
	case 4:
		return "cancelled"
	}
	return strconv.Itoa(s)
}

// cmdCloud is the escape hatch: any of the catalogued endpoints with any body.
func (a *app) cmdCloud(args []string) error {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	data := fs.String("d", "", "JSON body, or @file")
	var queries multiFlag
	fs.Var(&queries, "q", "query parameter k=v (repeatable)")
	signed := fs.Bool("signed", false, "force the IoT app-certificate signature headers")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: bambu cloud <GET|POST|PUT|DELETE> <service/path> [-d json|@file] [-q k=v]...")
	}
	method, path := strings.ToUpper(pos[0]), strings.TrimPrefix(pos[1], "/")
	q := url.Values{}
	for _, kvp := range queries {
		k, v, _ := strings.Cut(kvp, "=")
		q.Add(k, v)
	}
	var body any
	if *data != "" {
		if strings.HasPrefix(*data, "@") {
			b, err := os.ReadFile((*data)[1:])
			if err != nil {
				return err
			}
			body = b
		} else {
			body = *data
		}
	}
	req, err := a.api.newRequest(a.ctx, method, "/v1/cloud/"+path, q, body)
	if err != nil {
		return err
	}
	if *signed {
		req.Header.Set("X-Bambu-Signed", "1")
	}
	resp, err := a.api.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var raw json.RawMessage
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 300 {
		ae := &apiError{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, ae)
		if ae.Msg == "" {
			ae.Msg = string(raw)
		}
		return ae
	}
	var pretty any
	if json.Unmarshal(raw, &pretty) == nil {
		return a.emit(pretty)
	}
	fmt.Fprintln(a.out, string(raw))
	return nil
}

func (a *app) cmdEndpoints(args []string) error {
	filter := strings.ToLower(strings.Join(args, " "))
	eps := append([]*cloud.Endpoint(nil), cloud.Endpoints...)
	sort.Slice(eps, func(i, j int) bool { return eps[i].Path+eps[i].Method < eps[j].Path+eps[j].Method })
	var rows []*cloud.Endpoint
	for _, ep := range eps {
		if filter == "" || strings.Contains(strings.ToLower(ep.Method+" "+ep.Path+" "+ep.Name), filter) {
			rows = append(rows, ep)
		}
	}
	if a.json {
		return a.emit(rows)
	}
	tw := newTable(a.out)
	for _, ep := range rows {
		flags := ""
		if ep.Signed {
			flags = "signed"
		}
		tw.row(ep.Method, ep.Path, ep.Response, flags)
	}
	tw.flush()
	return nil
}

func (a *app) cmdLAN(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		if a.json {
			return a.emit(a.cfg.LAN)
		}
		if len(a.cfg.LAN) == 0 {
			fmt.Fprintln(a.out, "no LAN printers; add one with: bambu lan add <ip> <serial> <access code>")
			return nil
		}
		tw := newTable(a.out)
		tw.row("SERIAL", "IP", "NAME", "TLS")
		for _, l := range a.cfg.LAN {
			tls := "verified"
			if l.Insecure {
				tls = "insecure"
			}
			tw.row(l.Serial, l.IP, l.Name, tls)
		}
		tw.flush()
		return nil
	case "add":
		fs := flag.NewFlagSet("lan add", flag.ContinueOnError)
		name := fs.String("name", "", "display name")
		insecure := fs.Bool("insecure", false, "skip TLS verification (printers with replaced certificates)")
		pos, err := parseArgs(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 3 {
			return errors.New("usage: bambu lan add <ip> <serial> <access code> [-name N] [-insecure]")
		}
		lp := LANPrinter{IP: pos[0], Serial: pos[1], AccessCode: pos[2], Name: *name, Insecure: *insecure}
		if err := a.ensureLAN(&lp); err != nil {
			return fmt.Errorf("could not connect: %w", err)
		}
		if old := a.cfg.lanPrinter(lp.Serial); old != nil {
			*old = lp
		} else {
			a.cfg.LAN = append(a.cfg.LAN, lp)
		}
		if a.cfg.Printer == "" {
			a.cfg.Printer = lp.Serial
		}
		if err := a.cfg.save(); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "connected to %s at %s\n", lp.Serial, lp.IP)
		return nil
	case "rm", "remove":
		if len(args) != 2 {
			return errors.New("usage: bambu lan rm <serial>")
		}
		kept := a.cfg.LAN[:0]
		for _, l := range a.cfg.LAN {
			if l.Serial != args[1] {
				kept = append(kept, l)
			}
		}
		a.cfg.LAN = kept
		if a.cfg.Printer == args[1] {
			a.cfg.Printer = ""
		}
		_ = a.api.do(a.ctx, "DELETE", "/v1/lan/devices/"+args[1], nil, nil, nil)
		return a.cfg.save()
	}
	return fmt.Errorf("unknown lan action %q (add|list|rm)", args[0])
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
