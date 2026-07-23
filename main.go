package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── Data models ──────────────────────────────────────────────────────────────

type LogEntry struct {
	LineNum   int    `json:"line"`
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Source    string `json:"source"`
	Message   string `json:"message"`
	Category  string `json:"category"`
	Kind      string `json:"kind"`
}

type ProxySQLMeta struct {
	Version       string `json:"version"`
	LatestVersion string `json:"latest_version"`
	SHA1          string `json:"sha1"`
	UUID          string `json:"uuid"`
	ConfigFile    string `json:"config_file"`
	OS            string `json:"os"`
	OpenSSL       string `json:"openssl"`
	Datadir       string `json:"datadir"`
}

type ConfigEvent struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"` // LOAD or SAVE
	Target    string `json:"target"`
	Checksum  string `json:"checksum,omitempty"`
	Epoch     string `json:"epoch,omitempty"`
	LineNum   int    `json:"line"`
}

type BackendNode struct {
	Engine    string `json:"engine"`
	Hostgroup string `json:"hostgroup"`
	Hostname  string `json:"hostname"`
	Port      string `json:"port"`
	Weight    string `json:"weight"`
	Status    string `json:"status"`
	MaxConns  string `json:"max_conns"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
	LineNum   int    `json:"line"`
}

type TimelineEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Level     string `json:"level"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Source    string `json:"source"`
	Hostgroup string `json:"hostgroup,omitempty"`
	Status    string `json:"status,omitempty"`
	LineNum   int    `json:"line"`
}

type TableBlock struct {
	Title     string     `json:"title"`
	Engine    string     `json:"engine"`
	Kind      string     `json:"kind"`
	Headers   []string   `json:"headers"`
	Rows      [][]string `json:"rows"`
	LineStart int        `json:"line_start"`
	Timestamp string     `json:"timestamp"`
}

type Alert struct {
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Message   string `json:"message"`
	LineNum   int    `json:"line"`
}

type Analysis struct {
	File               string          `json:"file"`
	FileName           string          `json:"file_name"`
	TotalLines         int             `json:"total_lines"`
	Meta               ProxySQLMeta    `json:"meta"`
	Entries            []LogEntry      `json:"entries"`
	ConfigEvents       []ConfigEvent   `json:"config_events"`
	BackendNodes       []BackendNode   `json:"backend_nodes"`
	Timeline           []TimelineEvent `json:"timeline"`
	RecentTimeline     []TimelineEvent `json:"recent_timeline"`
	Tables             []TableBlock    `json:"tables"`
	Errors             []Alert         `json:"errors"`
	Warnings           []Alert         `json:"warnings"`
	LevelCounts        map[string]int  `json:"level_counts"`
	CategoryCounts     map[string]int  `json:"category_counts"`
	NodeStatusCounts   map[string]int  `json:"node_status_counts"`
	TimelineHostgroups []string        `json:"timeline_hostgroups"`
	NodeHostgroups     []string        `json:"node_hostgroups"`
	StartTime          string          `json:"start_time"`
	EndTime            string          `json:"end_time"`
	ParsedAt           string          `json:"parsed_at"`
	SearchIndex        string          `json:"search_index"`
}

// ── Regex ────────────────────────────────────────────────────────────────────

var (
	reStandard = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$`)
	reSource   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([^\s]+): \[(\w+)\] (.*)$`)
	reBanner   = regexp.MustCompile(`^(Standard|In memory) .+ rev\. .+ -- .+ -- .+$`)
	reHID      = regexp.MustCompile(`^HID: (\d+) , address: ([^ ]+) , port: (\d+) , .+ weight: (\d+) , status: (\w+) , max_connections: (\d+)`)
	reServer   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[INFO\] Creating new server in HG (\d+) : ([^:]+):(\d+) , .+ weight=(\d+), status=(\d+)`)
	reShun     = regexp.MustCompile(`Server ([^:]+):(\d+) missed \d+ heartbeats`)
	reVersion  = regexp.MustCompile(`ProxySQL version ([0-9][^\s]+)`)
	reLatest   = regexp.MustCompile(`Latest ProxySQL version available: ([^\s]+)`)
	reUUID     = regexp.MustCompile(`Using UUID: ([a-f0-9-]+)`)
	reConfig   = regexp.MustCompile(`Using config file (.+)$`)
	reOS       = regexp.MustCompile(`Detected OS: (.+)$`)
	reOpenSSL  = regexp.MustCompile(`Using OpenSSL version: (.+)$`)
	reSHA1     = regexp.MustCompile(`ProxySQL SHA1 checksum: ([a-f0-9]+)`)
	reDatadir  = regexp.MustCompile(`datadir \(([^)]+)\)`)
	reLoadSave = regexp.MustCompile(`Received (LOAD|SAVE) (.+?) TO (RUNTIME|DISK) command`)
	reChecksum = regexp.MustCompile(`Computed checksum for '(.+?)' was '(.+?)', with epoch '(\d+)'`)
	reTableRow = regexp.MustCompile(`^\|(.+)\|$`)
	reTableSep = regexp.MustCompile(`^\+[-+]+\+$`)
)

func categorize(level, msg, source string) string {
	lower := strings.ToLower(msg)

	if reLoadSave.MatchString(msg) || strings.Contains(lower, "computed checksum for 'load") ||
		strings.Contains(lower, "computed checksum for 'save") ||
		(strings.Contains(lower, "received load") || strings.Contains(lower, "received save")) {
		return "config_change"
	}
	if strings.Contains(lower, "dumping mysql_servers") || strings.Contains(lower, "dumping pgsql_servers") ||
		strings.Contains(lower, "dumping current mysql servers") ||
		strings.Contains(lower, "creating new server") ||
		strings.HasPrefix(lower, "hid:") {
		return "backend_nodes"
	}
	if strings.Contains(lower, "heartbeat") || strings.Contains(lower, "shunn") ||
		strings.Contains(lower, "monitor_ping") || strings.Contains(lower, "monitor ") {
		return "monitor"
	}
	if strings.Contains(lower, "dumping") {
		return "backend_nodes"
	}
	if reBanner.MatchString(msg) {
		return "component"
	}
	if strings.Contains(lower, "proxysql version") || strings.Contains(lower, "detected os") ||
		strings.Contains(lower, "openssl") || strings.Contains(lower, "jemalloc") ||
		strings.Contains(lower, "rlimit") {
		return "startup"
	}
	if strings.Contains(lower, "ssl") {
		return "ssl"
	}
	if level == "ERROR" {
		return "error"
	}
	if level == "WARNING" {
		return "warning"
	}
	return "general"
}

func tableEngine(title string) (engine, kind string) {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "pgsql"):
		engine = "pgsql"
	default:
		engine = "mysql"
	}
	switch {
	case strings.Contains(lower, "incoming"):
		kind = "incoming"
	case strings.Contains(lower, "join"):
		kind = "join"
	case strings.Contains(lower, "mysql_servers:") || strings.Contains(lower, "pgsql_servers:"):
		kind = "runtime"
	default:
		kind = "dump"
	}
	return
}

func statusLabel(code string) string {
	switch code {
	case "0":
		return "ONLINE"
	case "1":
		return "SHUNNED"
	case "2":
		return "OFFLINE_SOFT"
	case "3":
		return "OFFLINE_HARD"
	case "4":
		return "SHUNNED"
	default:
		return code
	}
}

func parseTableRow(line string) []string {
	m := reTableRow.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	parts := strings.Split(m[1], "|")
	var cells []string
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	return cells
}

func isTableLine(line string) bool {
	return reTableRow.MatchString(line) || reTableSep.MatchString(line)
}

func colIndex(headers []string, names ...string) int {
	for i, h := range headers {
		hl := strings.ToLower(strings.ReplaceAll(h, " ", "_"))
		for _, n := range names {
			if hl == n || strings.Contains(hl, n) {
				return i
			}
		}
	}
	return -1
}

func cellAt(row []string, idx int) string {
	if idx >= 0 && idx < len(row) {
		return row[idx]
	}
	return ""
}

func extractNodesFromTable(t TableBlock, ts string) []BackendNode {
	if len(t.Rows) == 0 {
		return nil
	}
	hg := colIndex(t.Headers, "hostgroup_id", "hid")
	host := colIndex(t.Headers, "hostname")
	port := colIndex(t.Headers, "port")
	weight := colIndex(t.Headers, "weight")
	status := colIndex(t.Headers, "status")
	maxc := colIndex(t.Headers, "max_connections", "max_conns")
	if host < 0 || port < 0 {
		return nil
	}

	var nodes []BackendNode
	for _, row := range t.Rows {
		hostname := cellAt(row, host)
		if hostname == "" || strings.Contains(hostname, "-") {
			continue
		}
		st := cellAt(row, status)
		if st != "" && st != "ONLINE" && st != "SHUNNED" {
			st = statusLabel(st)
		}
		if st == "" {
			st = "configured"
		}
		nodes = append(nodes, BackendNode{
			Engine:    t.Engine,
			Hostgroup: cellAt(row, hg),
			Hostname:  hostname,
			Port:      cellAt(row, port),
			Weight:    cellAt(row, weight),
			Status:    st,
			MaxConns:  cellAt(row, maxc),
			Source:    t.Title,
			Timestamp: ts,
			LineNum:   t.LineStart,
		})
	}
	return nodes
}

func parseLog(path string) (*Analysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	a := &Analysis{
		File:           path,
		FileName:       filepath.Base(path),
		LevelCounts:    make(map[string]int),
		CategoryCounts: make(map[string]int),
		ParsedAt:       time.Now().Format("2006-01-02 15:04:05"),
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	a.TotalLines = len(lines)

	var tableLines []string
	var tableStart int
	var tableTitle string
	var tableTS string
	var searchParts []string
	var lastTimestamp string

	addTimeline := func(ts, typ, level, title, detail, source, hg, status string, line int) {
		a.Timeline = append(a.Timeline, TimelineEvent{
			Timestamp: ts, Type: typ, Level: level,
			Title: title, Detail: detail, Source: source,
			Hostgroup: hg, Status: status, LineNum: line,
		})
	}

	flushTable := func() {
		if len(tableLines) < 2 {
			tableLines = nil
			return
		}
		var headers []string
		var rows [][]string
		for _, tl := range tableLines {
			cells := parseTableRow(tl)
			if cells == nil {
				continue
			}
			if headers == nil {
				headers = cells
				continue
			}
			if len(cells) == len(headers) {
				allDash := true
				for _, c := range cells {
					if c != "" && !strings.Contains(c, "-") {
						allDash = false
						break
					}
				}
				if !allDash {
					rows = append(rows, cells)
				}
			}
		}
		if len(headers) > 0 {
			engine, kind := tableEngine(tableTitle)
			tb := TableBlock{
				Title: tableTitle, Engine: engine, Kind: kind,
				Headers: headers, Rows: rows, LineStart: tableStart, Timestamp: tableTS,
			}
			a.Tables = append(a.Tables, tb)
			for _, n := range extractNodesFromTable(tb, tableTS) {
				a.BackendNodes = append(a.BackendNodes, n)
			}
		}
		tableLines = nil
		tableTitle = ""
		tableTS = ""
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		searchParts = append(searchParts, trimmed)

		if trimmed == "" {
			continue
		}

		if isTableLine(trimmed) {
			if len(tableLines) == 0 {
				tableStart = lineNum
				for j := i - 1; j >= 0 && j >= i-3; j-- {
					if m := reStandard.FindStringSubmatch(lines[j]); m != nil {
						tableTitle = m[3]
						tableTS = m[1]
						break
					}
				}
				if tableTS == "" {
					tableTS = lastTimestamp
				}
			}
			tableLines = append(tableLines, trimmed)
			a.Entries = append(a.Entries, LogEntry{
				LineNum: lineNum, Kind: "table", Message: trimmed, Category: "backend_nodes",
			})
			continue
		}
		if len(tableLines) > 0 {
			flushTable()
		}

		if reBanner.MatchString(trimmed) {
			a.Entries = append(a.Entries, LogEntry{
				LineNum: lineNum, Kind: "banner", Message: trimmed, Category: "component",
			})
			a.CategoryCounts["component"]++
			continue
		}

		if m := reHID.FindStringSubmatch(trimmed); m != nil {
			ts := lastTimestamp
			status := strings.ToUpper(m[5])
			node := BackendNode{
				Engine: "mysql", Hostgroup: m[1], Hostname: m[2], Port: m[3],
				Weight: m[4], Status: status, MaxConns: m[6],
				Source: "runtime HID dump", Timestamp: ts, LineNum: lineNum,
			}
			a.BackendNodes = append(a.BackendNodes, node)
			a.Entries = append(a.Entries, LogEntry{
				LineNum: lineNum, Kind: "server", Message: trimmed, Category: "backend_nodes",
			})

			// The HID line's status can be ONLINE, SHUNNED, OFFLINE_SOFT,
			// OFFLINE_HARD, or anything else ProxySQL reports — the
			// timeline entry (type, title, dot color) must reflect the
			// actual status, not always "ONLINE".
			var tlType string
			switch status {
			case "ONLINE":
				tlType = "node_online"
			case "SHUNNED":
				tlType = "node_shunned"
			case "OFFLINE_SOFT":
				tlType = "node_offline_soft"
			case "OFFLINE_HARD":
				tlType = "node_offline_hard"
			default:
				tlType = "node_status"
			}
			addTimeline(ts, tlType, "INFO",
				fmt.Sprintf("Node %s: %s:%s (HG %s)", status, m[2], m[3], m[1]),
				trimmed, "", m[1], status, lineNum)
			continue
		}

		var entry LogEntry
		entry.LineNum = lineNum
		entry.Kind = "log"

		if m := reSource.FindStringSubmatch(trimmed); m != nil {
			entry.Timestamp, entry.Source, entry.Level, entry.Message = m[1], m[2], m[3], m[4]
		} else if m := reStandard.FindStringSubmatch(trimmed); m != nil {
			entry.Timestamp, entry.Level, entry.Message = m[1], m[2], m[3]
		} else {
			entry.Message = trimmed
			entry.Level = "OTHER"
			entry.Kind = "other"
		}

		entry.Category = categorize(entry.Level, entry.Message, entry.Source)
		a.Entries = append(a.Entries, entry)

		if entry.Level != "" && entry.Level != "OTHER" {
			a.LevelCounts[entry.Level]++
		} else if entry.Kind == "other" {
			a.LevelCounts["OTHER"]++
		}
		a.CategoryCounts[entry.Category]++

		if entry.Timestamp != "" {
			lastTimestamp = entry.Timestamp
			if a.StartTime == "" {
				a.StartTime = entry.Timestamp
			}
			a.EndTime = entry.Timestamp
		}

		// Meta extraction
		if m := reVersion.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.Version = m[1]
		}
		if m := reLatest.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.LatestVersion = m[1]
		}
		if m := reUUID.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.UUID = m[1]
		}
		if m := reConfig.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.ConfigFile = m[1]
		}
		if m := reOS.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.OS = m[1]
		}
		if m := reOpenSSL.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.OpenSSL = m[1]
		}
		if m := reSHA1.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.SHA1 = m[1]
		}
		if m := reDatadir.FindStringSubmatch(entry.Message); m != nil {
			a.Meta.Datadir = m[1]
		}

		// Config events
		if m := reLoadSave.FindStringSubmatch(entry.Message); m != nil {
			ce := ConfigEvent{
				Timestamp: entry.Timestamp,
				Action:    m[1],
				Target:    m[2] + " TO " + m[3],
				LineNum:   lineNum,
			}
			a.ConfigEvents = append(a.ConfigEvents, ce)
			addTimeline(entry.Timestamp, "config_"+strings.ToLower(m[1]), "INFO",
				fmt.Sprintf("%s %s", m[1], m[2]),
				entry.Message, entry.Source, "", "", lineNum)
		}
		if m := reChecksum.FindStringSubmatch(entry.Message); m != nil {
			ce := ConfigEvent{
				Timestamp: entry.Timestamp,
				Action:    "LOAD",
				Target:    m[1],
				Checksum:  m[2],
				Epoch:     m[3],
				LineNum:   lineNum,
			}
			a.ConfigEvents = append(a.ConfigEvents, ce)
			addTimeline(entry.Timestamp, "config_load", "INFO",
				"LOAD "+m[1],
				fmt.Sprintf("checksum %s (epoch %s)", m[2], m[3]), entry.Source, "", "", lineNum)
		}

		// Server creation
		if m := reServer.FindStringSubmatch(trimmed); m != nil {
			node := BackendNode{
				Engine: "mysql", Hostgroup: m[2], Hostname: m[3], Port: m[4],
				Weight: m[5], Status: statusLabel(m[6]),
				Source: "server creation", Timestamp: m[1], LineNum: lineNum,
			}
			a.BackendNodes = append(a.BackendNodes, node)
			addTimeline(m[1], "node_created", "INFO",
				fmt.Sprintf("Created node %s:%s in HG %s", m[3], m[4], m[2]),
				entry.Message, entry.Source, m[2], node.Status, lineNum)
		}

		// Alerts
		if entry.Level == "ERROR" {
			alert := Alert{Level: entry.Level, Timestamp: entry.Timestamp,
				Source: entry.Source, Message: entry.Message, LineNum: lineNum}
			a.Errors = append(a.Errors, alert)
			addTimeline(entry.Timestamp, "error", "ERROR", entry.Message, entry.Source, entry.Source, "", "", lineNum)
			if m := reShun.FindStringSubmatch(entry.Message); m != nil {
				a.BackendNodes = append(a.BackendNodes, BackendNode{
					Engine: "mysql", Hostname: m[1], Port: m[2], Status: "SHUNNED",
					Source: "monitor shun", Timestamp: entry.Timestamp, LineNum: lineNum,
				})
				addTimeline(entry.Timestamp, "node_shunned", "ERROR",
					fmt.Sprintf("Node SHUNNED: %s:%s", m[1], m[2]),
					entry.Message, entry.Source, "", "SHUNNED", lineNum)
			}
		}
		if entry.Level == "WARNING" {
			alert := Alert{Level: entry.Level, Timestamp: entry.Timestamp,
				Source: entry.Source, Message: entry.Message, LineNum: lineNum}
			a.Warnings = append(a.Warnings, alert)
			addTimeline(entry.Timestamp, "warning", "WARNING", entry.Message, entry.Source, entry.Source, "", "", lineNum)
		}

		if entry.Category == "startup" && entry.Timestamp != "" {
			addTimeline(entry.Timestamp, "startup", entry.Level, entry.Message, "", entry.Source, "", "", lineNum)
		}

		// Every "Dumping ..." line is a distinct, timestamped moment where
		// ProxySQL captured server/config state — surface it on the
		// timeline in its own right, not just the node status changes
		// derived from it.
		if entry.Category == "backend_nodes" && entry.Timestamp != "" &&
			strings.HasPrefix(strings.ToLower(entry.Message), "dumping") {
			addTimeline(entry.Timestamp, "dump", entry.Level, entry.Message, "", entry.Source, "", "", lineNum)
		}
	}

	if len(tableLines) > 0 {
		flushTable()
	}

	sort.Slice(a.Timeline, func(i, j int) bool {
		if a.Timeline[i].Timestamp != a.Timeline[j].Timestamp {
			return a.Timeline[i].Timestamp < a.Timeline[j].Timestamp
		}
		return a.Timeline[i].LineNum < a.Timeline[j].LineNum
	})

	// Overview shows the most recent activity, newest first — take the
	// tail of the (oldest-first sorted) timeline and reverse it.
	const recentN = 20
	start := len(a.Timeline) - recentN
	if start < 0 {
		start = 0
	}
	for i := len(a.Timeline) - 1; i >= start; i-- {
		a.RecentTimeline = append(a.RecentTimeline, a.Timeline[i])
	}

	a.NodeStatusCounts = map[string]int{}
	for _, n := range a.BackendNodes {
		st := n.Status
		if st == "" {
			st = "UNKNOWN"
		}
		a.NodeStatusCounts[st]++
	}

	hgSet := map[string]bool{}
	for _, e := range a.Timeline {
		if e.Hostgroup != "" {
			hgSet[e.Hostgroup] = true
		}
	}
	for hg := range hgSet {
		a.TimelineHostgroups = append(a.TimelineHostgroups, hg)
	}
	sort.Slice(a.TimelineHostgroups, func(i, j int) bool {
		vi, ei := strconv.Atoi(a.TimelineHostgroups[i])
		vj, ej := strconv.Atoi(a.TimelineHostgroups[j])
		if ei == nil && ej == nil {
			return vi < vj
		}
		return a.TimelineHostgroups[i] < a.TimelineHostgroups[j]
	})

	nodeHgSet := map[string]bool{}
	for _, n := range a.BackendNodes {
		if n.Hostgroup != "" {
			nodeHgSet[n.Hostgroup] = true
		}
	}
	for hg := range nodeHgSet {
		a.NodeHostgroups = append(a.NodeHostgroups, hg)
	}
	sort.Slice(a.NodeHostgroups, func(i, j int) bool {
		vi, ei := strconv.Atoi(a.NodeHostgroups[i])
		vj, ej := strconv.Atoi(a.NodeHostgroups[j])
		if ei == nil && ej == nil {
			return vi < vj
		}
		return a.NodeHostgroups[i] < a.NodeHostgroups[j]
	})

	sort.Slice(a.ConfigEvents, func(i, j int) bool {
		if a.ConfigEvents[i].Timestamp != a.ConfigEvents[j].Timestamp {
			return a.ConfigEvents[i].Timestamp < a.ConfigEvents[j].Timestamp
		}
		return a.ConfigEvents[i].LineNum < a.ConfigEvents[j].LineNum
	})

	a.SearchIndex = strings.ToLower(strings.Join(searchParts, "\n"))
	return a, nil
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

var analysis *Analysis

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ProxySQL Log Analyzer{{if .Meta.Version}} — v{{.Meta.Version}}{{end}}</title>
<style>
:root {
  --bg: #0b0f14;
  --surface: #131a24;
  --surface2: #1a2433;
  --surface3: #212d3d;
  --border: #2a3848;
  --text: #e8edf4;
  --muted: #7d8fa3;
  --info: #3b9eff;
  --warn: #f5a623;
  --error: #ff4d4f;
  --ok: #22c55e;
  --accent: #7c6cff;
  --config: #a78bfa;
  --node: #06b6d4;
  --radius: 10px;
  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  --mono: ui-monospace, 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; line-height: 1.55; }

/* ── Header ── */
.hero {
  background: linear-gradient(160deg, #141c28 0%, #0b0f14 60%);
  border-bottom: 1px solid var(--border);
  padding: 1.75rem 2rem 1.5rem;
}
.hero-inner { max-width: 1440px; margin: 0 auto; }
.hero-top { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }
.brand { display: flex; align-items: center; gap: 0.85rem; }
.logo {
  width: 44px; height: 44px; border-radius: 10px;
  background: linear-gradient(135deg, var(--accent), #3b9eff);
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 0.75rem; color: #fff; letter-spacing: -0.03em;
}
.brand h1 { font-size: 1.35rem; font-weight: 700; letter-spacing: -0.03em; }
.brand h1 em { font-style: normal; color: var(--accent); }
.brand .sub { font-size: 0.8rem; color: var(--muted); margin-top: 0.15rem; }
.version-badge {
  display: inline-flex; align-items: center; gap: 0.5rem;
  background: rgba(124,108,255,0.15); border: 1px solid rgba(124,108,255,0.35);
  color: #c4b5fd; padding: 0.35rem 0.85rem; border-radius: 999px;
  font-size: 0.85rem; font-weight: 600; font-family: var(--mono);
}
.version-badge .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); }
.file-badge {
  display: inline-flex; align-items: center; gap: 0.4rem;
  background: var(--surface2); border: 1px solid var(--border);
  padding: 0.35rem 0.75rem; border-radius: 999px; font-size: 0.78rem; color: var(--muted);
}
.file-badge strong { color: var(--text); font-weight: 500; }

.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0.65rem;
}
.meta-item {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.65rem 0.85rem;
}
.meta-item .k { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); margin-bottom: 0.15rem; }
.meta-item .v { font-size: 0.82rem; font-family: var(--mono); word-break: break-all; color: var(--text); }

/* ── Search ── */
.search-bar {
  max-width: 1440px; margin: 0 auto; padding: 1rem 2rem 0;
  position: sticky; top: 0; z-index: 100;
  background: linear-gradient(var(--bg) 70%, transparent);
}
.search-wrap {
  display: flex; align-items: center; gap: 0.75rem;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.6rem 1rem;
  transition: border-color 0.15s;
}
.search-wrap:focus-within { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(124,108,255,0.15); }
.search-wrap svg { flex-shrink: 0; color: var(--muted); }
.search-wrap input {
  flex: 1; background: none; border: none; color: var(--text);
  font-family: var(--font); font-size: 0.9rem; outline: none;
}
.search-wrap input::placeholder { color: var(--muted); }
.search-count { font-size: 0.78rem; color: var(--muted); white-space: nowrap; }

.daterange-wrap {
  display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
  margin-top: 0.6rem; padding: 0.55rem 1rem;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  font-size: 0.8rem; color: var(--muted);
}
.daterange-wrap label { display: flex; align-items: center; gap: 0.4rem; }
.daterange-wrap input[type=datetime-local] {
  background: var(--surface2); border: 1px solid var(--border); color: var(--text);
  padding: 0.3rem 0.5rem; border-radius: 6px; font-family: var(--mono); font-size: 0.78rem;
  color-scheme: dark;
}
.daterange-wrap input[type=datetime-local]:focus { border-color: var(--accent); outline: none; }
.daterange-hint { font-size: 0.72rem; font-family: var(--mono); color: var(--text-faint, var(--muted)); }
#clear-filters {
  margin-left: auto; background: transparent; border: 1px solid var(--border); color: var(--muted);
  padding: 0.35rem 0.75rem; border-radius: 8px; font-size: 0.78rem; cursor: pointer;
  font-family: var(--font); transition: all 0.15s;
}
#clear-filters:hover { color: var(--error); border-color: var(--error); }

/* ── Layout ── */
.container { max-width: 1440px; margin: 0 auto; padding: 1.25rem 2rem 3rem; }

.stats {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 0.75rem; margin-bottom: 1.25rem;
}
.stat {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.85rem 1rem;
}
.stat .label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.stat .value { font-size: 1.5rem; font-weight: 700; margin-top: 0.15rem; font-family: var(--mono); }
.stat.info .value { color: var(--info); }
.stat.warn .value { color: var(--warn); }
.stat.error .value { color: var(--error); }
.stat.config .value { color: var(--config); }
.stat.node .value { color: var(--node); }

.tabs {
  display: flex; gap: 0.3rem; margin-bottom: 1rem; flex-wrap: wrap;
  border-bottom: 1px solid var(--border); padding-bottom: 0.75rem;
}
.tab {
  background: transparent; border: 1px solid transparent;
  color: var(--muted); padding: 0.45rem 0.9rem; border-radius: 8px;
  cursor: pointer; font-size: 0.82rem; font-family: var(--font); font-weight: 500;
  transition: all 0.15s;
}
.tab:hover { color: var(--text); background: var(--surface); }
.tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.tab .cnt {
  display: inline-block; background: rgba(255,255,255,0.15);
  padding: 0.05rem 0.4rem; border-radius: 999px; font-size: 0.68rem; margin-left: 0.3rem;
}
.tab:not(.active) .cnt { background: var(--surface2); color: var(--muted); }

.panel { display: none; }
.panel.active { display: block; }

.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); overflow: hidden; margin-bottom: 1rem;
}
.card-header {
  padding: 0.75rem 1rem; background: var(--surface2);
  border-bottom: 1px solid var(--border);
  font-size: 0.82rem; font-weight: 600;
  display: flex; align-items: center; justify-content: space-between;
}
.card-header .tag {
  font-size: 0.68rem; font-weight: 600; padding: 0.15rem 0.5rem;
  border-radius: 4px; text-transform: uppercase; letter-spacing: 0.04em;
}

/* ── Timeline ── */
.timeline { position: relative; padding: 0.5rem 0; }
.tl-item {
  display: grid; grid-template-columns: 140px 28px 1fr;
  gap: 0.75rem; padding: 0.65rem 1rem; border-bottom: 1px solid var(--border);
  font-size: 0.82rem; align-items: start;
}
.tl-item:last-child { border-bottom: none; }
.tl-item:hover { background: var(--surface2); }
.tl-item.hidden { display: none; }
.tl-time { color: var(--muted); font-family: var(--mono); font-size: 0.75rem; white-space: nowrap; }
.tl-dot {
  width: 12px; height: 12px; border-radius: 50%; margin-top: 0.3rem;
  border: 2px solid var(--border); background: var(--surface3);
}
.tl-dot.config_load, .tl-dot.config_save { background: var(--config); border-color: var(--config); }
.tl-dot.error, .tl-dot.node_shunned, .tl-dot.node_offline_soft, .tl-dot.node_offline_hard { background: var(--error); border-color: var(--error); }
.tl-dot.warning { background: var(--warn); border-color: var(--warn); }
.tl-dot.node_created, .tl-dot.node_online { background: var(--ok); border-color: var(--ok); }
.tl-dot.startup { background: var(--info); border-color: var(--info); }
.tl-dot.dump { background: var(--node); border-color: var(--node); }
.tl-dot.node_status { background: var(--muted); border-color: var(--muted); }
.tl-title { font-weight: 500; margin-bottom: 0.15rem; }
.tl-detail { color: var(--muted); font-size: 0.78rem; font-family: var(--mono); word-break: break-word; }
.tl-src { color: var(--accent); font-size: 0.72rem; margin-top: 0.2rem; }
.tl-line { color: var(--muted); font-size: 0.72rem; }

/* ── Config events ── */
.config-row {
  display: grid; grid-template-columns: 155px 70px 1fr auto;
  gap: 0.75rem; padding: 0.65rem 1rem; border-bottom: 1px solid var(--border);
  font-size: 0.82rem; align-items: center;
}
.config-row:hover { background: var(--surface2); }
.config-row.hidden { display: none; }
.action-load { color: var(--config); font-weight: 700; font-family: var(--mono); }
.action-save { color: var(--ok); font-weight: 700; font-family: var(--mono); }
.checksum { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }

/* ── Alerts ── */
.alert-card { padding: 1rem; border-bottom: 1px solid var(--border); }
.alert-card:last-child { border-bottom: none; }
.alert-card.hidden { display: none; }
.card.hidden, .dump-card.hidden { display: none; }
.alert-card.error-alert {
  background: rgba(255,77,79,0.06); border-left: 4px solid var(--error);
}
.alert-card.warn-alert {
  background: rgba(245,166,35,0.06); border-left: 4px solid var(--warn);
}
.alert-head { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin-bottom: 0.5rem; }
.alert-icon {
  width: 28px; height: 28px; border-radius: 6px;
  display: flex; align-items: center; justify-content: center; font-size: 0.85rem;
}
.error-alert .alert-icon { background: rgba(255,77,79,0.2); color: var(--error); }
.warn-alert .alert-icon { background: rgba(245,166,35,0.2); color: var(--warn); }
.alert-msg { font-size: 0.88rem; line-height: 1.5; }
.alert-meta { font-size: 0.75rem; color: var(--muted); font-family: var(--mono); margin-top: 0.4rem; }

/* ── Nodes ── */
.node-status {
  display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
  font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
}
.node-status.ONLINE, .node-status.online, .node-status.configured { background: rgba(34,197,94,0.15); color: var(--ok); }
.node-status.SHUNNED, .node-status.shunned { background: rgba(255,77,79,0.15); color: var(--error); }
.node-status.OFFLINE_SOFT, .node-status.offline_soft { background: rgba(224,169,64,0.15); color: var(--warn, #e0a940); }
.node-status.OFFLINE_HARD, .node-status.offline_hard { background: rgba(226,86,77,0.18); color: var(--error); }
.node-status.created { background: rgba(59,158,255,0.15); color: var(--info); }
.engine-tag { font-size: 0.68rem; padding: 0.1rem 0.4rem; border-radius: 4px; background: var(--surface3); color: var(--muted); }

.status-filter-row {
  display: flex; flex-wrap: wrap; gap: 0.5rem;
  padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
}
.status-chip {
  display: inline-flex; align-items: center; gap: 0.4rem;
  background: var(--surface2); border: 1px solid var(--border); color: var(--muted);
  padding: 0.35rem 0.75rem; border-radius: 100px; font-size: 0.76rem; font-family: var(--mono);
  cursor: pointer; transition: all 0.15s;
}
.status-chip:hover { color: var(--text); border-color: var(--muted); }
.status-chip .cnt {
  background: var(--surface3); color: var(--text); font-weight: 700;
  padding: 0.05rem 0.4rem; border-radius: 100px; font-size: 0.72rem;
}
.status-chip.active { color: var(--bg); border-color: transparent; }
.status-chip.active .cnt { background: rgba(0,0,0,0.2); color: inherit; }
.status-chip[data-status=""].active { background: var(--accent); }
.status-chip[data-status="ONLINE"].active { background: var(--ok); }
.status-chip[data-status="SHUNNED"].active { background: var(--error); }
.status-chip[data-status="OFFLINE_SOFT"].active { background: #e0a940; }
.status-chip[data-status="OFFLINE_HARD"].active { background: var(--error); }
.status-chip[data-status="UNKNOWN"].active { background: var(--muted); }

table.data { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
table.data th {
  background: var(--surface2); padding: 0.55rem 0.85rem; text-align: left;
  border-bottom: 1px solid var(--border); color: var(--muted);
  font-weight: 600; white-space: nowrap; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em;
}
table.data td { padding: 0.5rem 0.85rem; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 0.78rem; }
table.data tr:hover td { background: var(--surface2); }
table.data tr.hidden { display: none; }

/* ── Logs ── */
.log-list { max-height: 650px; overflow-y: auto; }
.log-row {
  display: grid; grid-template-columns: 58px 148px 72px 100px 1fr;
  gap: 0.6rem; padding: 0.4rem 1rem; border-bottom: 1px solid var(--border);
  font-size: 0.76rem; align-items: start;
}
.log-row:hover { background: var(--surface2); }
.log-row.hidden { display: none; }
.log-row mark { background: rgba(124,108,255,0.35); color: inherit; border-radius: 2px; padding: 0 1px; }
.line-num { color: var(--muted); text-align: right; font-family: var(--mono); }
.ts { color: var(--muted); font-family: var(--mono); white-space: nowrap; font-size: 0.72rem; }
.badge {
  display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px;
  font-size: 0.65rem; font-weight: 700; text-transform: uppercase; text-align: center;
}
.badge-INFO { background: rgba(59,158,255,0.18); color: var(--info); }
.badge-WARNING { background: rgba(245,166,35,0.18); color: var(--warn); }
.badge-ERROR { background: rgba(255,77,79,0.18); color: var(--error); }
.badge-OTHER { background: rgba(125,143,163,0.18); color: var(--muted); }
.cat-badge { font-size: 0.62rem; color: var(--muted); background: var(--surface3); padding: 0.1rem 0.35rem; border-radius: 3px; }
.msg { word-break: break-word; font-family: var(--mono); font-size: 0.75rem; }
.msg .src { color: var(--accent); font-size: 0.7rem; display: block; margin-bottom: 0.1rem; }

.empty { padding: 2.5rem; text-align: center; color: var(--muted); font-size: 0.88rem; }
.toolbar { display: flex; gap: 0.6rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
.toolbar select {
  background: var(--surface); border: 1px solid var(--border); color: var(--text);
  padding: 0.45rem 0.7rem; border-radius: 8px; font-family: var(--font); font-size: 0.8rem;
}

@media (max-width: 768px) {
  .hero, .container, .search-bar { padding-left: 1rem; padding-right: 1rem; }
  .log-row { grid-template-columns: 50px 1fr; }
  .config-row { grid-template-columns: 1fr; }
  .tl-item { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<header class="hero">
  <div class="hero-inner">
    <div class="hero-top">
      <div class="brand">
        <div class="logo">PSQL</div>
        <div>
          <h1><em>ProxySQL</em> Log Analyzer</h1>
          <div class="sub">Static file analysis &mdash; not a live stream</div>
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center">
        {{if .Meta.Version}}
        <div class="version-badge"><span class="dot"></span> v{{.Meta.Version}}</div>
        {{else}}
        <div class="version-badge" style="opacity:0.6">Version not detected</div>
        {{end}}
        <div class="file-badge"><strong>{{.FileName}}</strong> &middot; {{.TotalLines}} lines &middot; parsed {{.ParsedAt}}</div>
      </div>
    </div>
    <div class="meta-grid">
      {{if .Meta.LatestVersion}}<div class="meta-item"><div class="k">Latest Available</div><div class="v">{{.Meta.LatestVersion}}</div></div>{{end}}
      {{if .Meta.UUID}}<div class="meta-item"><div class="k">UUID</div><div class="v">{{.Meta.UUID}}</div></div>{{end}}
      {{if .Meta.ConfigFile}}<div class="meta-item"><div class="k">Config File</div><div class="v">{{.Meta.ConfigFile}}</div></div>{{end}}
      {{if .Meta.OpenSSL}}<div class="meta-item"><div class="k">OpenSSL</div><div class="v">{{.Meta.OpenSSL}}</div></div>{{end}}
      {{if .Meta.OS}}<div class="meta-item"><div class="k">Operating System</div><div class="v">{{.Meta.OS}}</div></div>{{end}}
      {{if .Meta.SHA1}}<div class="meta-item"><div class="k">SHA1 Checksum</div><div class="v">{{.Meta.SHA1}}</div></div>{{end}}
      {{if .Meta.Datadir}}<div class="meta-item"><div class="k">Data Directory</div><div class="v">{{.Meta.Datadir}}</div></div>{{end}}
      {{if .StartTime}}<div class="meta-item"><div class="k">Log Time Range</div><div class="v">{{.StartTime}} &rarr; {{.EndTime}}</div></div>{{end}}
    </div>
  </div>
</header>

<div class="search-bar">
  <div class="search-wrap">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
    <input type="search" id="global-search" placeholder="Search everything — messages, nodes, config events, errors, tables..." autocomplete="off">
    <span class="search-count" id="search-count"></span>
  </div>
  <div class="daterange-wrap">
    <label>From <input type="datetime-local" id="date-from" step="1"></label>
    <label>To <input type="datetime-local" id="date-to" step="1"></label>
    <span class="daterange-hint">{{if .StartTime}}log spans {{.StartTime}} &rarr; {{.EndTime}}{{end}}</span>
    <button id="clear-filters" type="button">Clear filters</button>
  </div>
</div>

<div class="container">
  <div class="stats">
    <div class="stat"><div class="label">Total Lines</div><div class="value">{{.TotalLines}}</div></div>
    <div class="stat info"><div class="label">Info</div><div class="value">{{index .LevelCounts "INFO"}}</div></div>
    <div class="stat warn"><div class="label">Warnings</div><div class="value">{{index .LevelCounts "WARNING"}}</div></div>
    <div class="stat error"><div class="label">Errors</div><div class="value">{{index .LevelCounts "ERROR"}}</div></div>
    <div class="stat config"><div class="label">Config Events</div><div class="value">{{len .ConfigEvents}}</div></div>
    <div class="stat node"><div class="label">Backend Node Events</div><div class="value">{{len .BackendNodes}}</div></div>
  </div>

  <div class="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="timeline">Event Timeline<span class="cnt">{{len .Timeline}}</span></button>
    <button class="tab" data-tab="config">Config Changes<span class="cnt">{{len .ConfigEvents}}</span></button>
    <button class="tab" data-tab="nodes">Backend Node Events<span class="cnt">{{len .BackendNodes}}</span></button>
    <button class="tab" data-tab="errors">Errors<span class="cnt">{{len .Errors}}</span></button>
    <button class="tab" data-tab="warnings">Warnings<span class="cnt">{{len .Warnings}}</span></button>
    <button class="tab" data-tab="dumps">Node Dumps<span class="cnt">{{len .Tables}}</span></button>
    <button class="tab" data-tab="logs">Full Log</button>
  </div>

  <!-- Overview -->
  <div id="overview" class="panel active">
    <div class="card">
      <div class="card-header">ProxySQL Instance Details</div>
      <div style="padding:1rem;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:0.75rem">
        <div class="meta-item"><div class="k">ProxySQL Version</div><div class="v" style="font-size:1.1rem;color:var(--accent)">{{if .Meta.Version}}{{.Meta.Version}}{{else}}—{{end}}</div></div>
        <div class="meta-item"><div class="k">Log File</div><div class="v">{{.File}}</div></div>
        <div class="meta-item"><div class="k">Analysis Mode</div><div class="v">Static file (provided at startup via -file flag)</div></div>
        <div class="meta-item"><div class="k">Config LOAD/SAVE Operations</div><div class="v">{{len .ConfigEvents}} events detected</div></div>
        <div class="meta-item"><div class="k">Backend Node Events Tracked</div><div class="v">{{len .BackendNodes}} status entries across dumps &amp; runtime (not distinct node count)</div></div>
        <div class="meta-item"><div class="k">Issues Found</div><div class="v">{{len .Errors}} errors, {{len .Warnings}} warnings</div></div>
      </div>
    </div>
    {{if .RecentTimeline}}
    <div class="card">
      <div class="card-header">Recent Events<span class="tag" style="background:rgba(124,108,255,0.15);color:var(--accent)">last {{len .RecentTimeline}}, newest first</span></div>
      <div class="timeline" id="overview-timeline">
      {{range .RecentTimeline}}
        <div class="tl-item" data-search="{{lower .Timestamp}} {{lower .Type}} {{lower .Title}} {{lower .Detail}} {{lower .Source}}" data-ts="{{.Timestamp}}">
          <div class="tl-time">{{.Timestamp}}</div>
          <div class="tl-dot {{.Type}}"></div>
          <div>
            <div class="tl-title">{{.Title}}</div>
            {{if .Detail}}<div class="tl-detail">{{.Detail}}</div>{{end}}
            <div class="tl-line">Line {{.LineNum}}</div>
          </div>
        </div>
      {{end}}
      </div>
    </div>
    {{end}}
  </div>

  <!-- Event Timeline -->
  <div id="timeline" class="panel">
    <div class="card">
      <div class="card-header">Chronological Event Timeline<span class="tag" style="background:rgba(124,108,255,0.15);color:var(--accent)">{{len .Timeline}} events</span></div>
      <div class="status-filter-row" id="timeline-filter-row">
        <label style="display:flex;align-items:center;gap:0.4rem;font-size:0.76rem;color:var(--muted);font-family:var(--mono)">
          HG/HID
          <select id="timeline-hg-filter" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:0.3rem 0.5rem;border-radius:6px;font-family:var(--mono);font-size:0.76rem">
            <option value="">All</option>
            {{range .TimelineHostgroups}}<option value="{{.}}">HG {{.}}</option>{{end}}
          </select>
        </label>
        <button class="status-chip active" data-tl-status="">All statuses</button>
        <button class="status-chip" data-tl-status="ONLINE">status: ONLINE</button>
        <button class="status-chip" data-tl-status="SHUNNED">status: SHUNNED</button>
        <button class="status-chip" data-tl-status="OFFLINE_SOFT">status: OFFLINE_SOFT</button>
        <button class="status-chip" data-tl-status="OFFLINE_HARD">status: OFFLINE_HARD</button>
      </div>
      <div class="timeline" id="event-timeline">
      {{range .Timeline}}
        <div class="tl-item" data-search="{{lower .Timestamp}} {{lower .Type}} {{lower .Title}} {{lower .Detail}} {{lower .Source}} {{lower .Level}}" data-ts="{{.Timestamp}}" data-tl-hg="{{.Hostgroup}}" data-tl-status="{{.Status}}">
          <div class="tl-time">{{.Timestamp}}</div>
          <div class="tl-dot {{.Type}}"></div>
          <div>
            <div class="tl-title">{{.Title}}</div>
            {{if .Detail}}<div class="tl-detail">{{.Detail}}</div>{{end}}
            {{if .Source}}<div class="tl-src">{{.Source}}</div>{{end}}
            <div class="tl-line">Line {{.LineNum}} &middot; {{.Type}}{{if .Hostgroup}} &middot; HG {{.Hostgroup}}{{end}}{{if .Status}} &middot; {{.Status}}{{end}}</div>
          </div>
        </div>
      {{else}}
        <div class="empty">No timeline events parsed.</div>
      {{end}}
      </div>
      <div class="empty" id="timeline-empty-filtered" style="display:none">No events match the current HG/status filter.</div>
    </div>
  </div>

  <!-- Config Changes -->
  <div id="config" class="panel">
    <div class="card">
      <div class="card-header">Configuration Changes (LOAD / SAVE)<span class="tag" style="background:rgba(167,139,250,0.15);color:var(--config)">Admin operations</span></div>
      {{range .ConfigEvents}}
      <div class="config-row" data-search="{{lower .Timestamp}} {{lower .Action}} {{lower .Target}} {{lower .Checksum}} {{lower .Epoch}}" data-ts="{{.Timestamp}}">
        <span class="ts">{{.Timestamp}}</span>
        <span class="{{if eq .Action "SAVE"}}action-save{{else}}action-load{{end}}">{{.Action}}</span>
        <span>{{.Target}}{{if .Checksum}} <span class="checksum">{{.Checksum}}</span>{{end}}</span>
        <span class="line-num">L{{.LineNum}}</span>
      </div>
      {{else}}
      <div class="empty">No LOAD/SAVE configuration events found.</div>
      {{end}}
    </div>
  </div>

  <!-- Backend Nodes -->
  <div id="nodes" class="panel">
    <div class="card">
      <div class="card-header">Backend Node Events &amp; Status Over Time<span class="tag" style="background:rgba(6,182,212,0.15);color:var(--node)">Every status sighting from dumps &amp; runtime — same node may repeat</span></div>
      <div class="status-filter-row" id="status-filter-row">
        <label style="display:flex;align-items:center;gap:0.4rem;font-size:0.76rem;color:var(--muted);font-family:var(--mono)">
          HG/HID
          <select id="node-hg-filter" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:0.3rem 0.5rem;border-radius:6px;font-family:var(--mono);font-size:0.76rem">
            <option value="">All</option>
            {{range .NodeHostgroups}}<option value="{{.}}">HG {{.}}</option>{{end}}
          </select>
        </label>
        <button class="status-chip active" data-status="">All <span class="cnt">{{len .BackendNodes}}</span></button>
        <button class="status-chip" data-status="ONLINE">status: ONLINE <span class="cnt">{{index .NodeStatusCounts "ONLINE"}}</span></button>
        <button class="status-chip" data-status="SHUNNED">status: SHUNNED <span class="cnt">{{index .NodeStatusCounts "SHUNNED"}}</span></button>
        <button class="status-chip" data-status="OFFLINE_SOFT">status: OFFLINE_SOFT <span class="cnt">{{index .NodeStatusCounts "OFFLINE_SOFT"}}</span></button>
        <button class="status-chip" data-status="OFFLINE_HARD">status: OFFLINE_HARD <span class="cnt">{{index .NodeStatusCounts "OFFLINE_HARD"}}</span></button>
        {{if index .NodeStatusCounts "UNKNOWN"}}<button class="status-chip" data-status="UNKNOWN">status: UNKNOWN <span class="cnt">{{index .NodeStatusCounts "UNKNOWN"}}</span></button>{{end}}
      </div>
      <div style="overflow-x:auto">
        <table class="data" id="nodes-table">
          <thead><tr>
            <th>Time</th><th>Engine</th><th>Hostgroup</th><th>Hostname</th><th>Port</th>
            <th>Weight</th><th>Status</th><th>Max Conns</th><th>Source</th><th>Line</th>
          </tr></thead>
          <tbody>
          {{range .BackendNodes}}
          <tr data-search="{{lower .Timestamp}} {{lower .Engine}} {{lower .Hostgroup}} {{lower .Hostname}} {{lower .Port}} {{lower .Status}} {{lower .Source}}" data-ts="{{.Timestamp}}" data-status="{{.Status}}" data-hg="{{.Hostgroup}}">
            <td>{{.Timestamp}}</td>
            <td><span class="engine-tag">{{.Engine}}</span></td>
            <td>{{.Hostgroup}}</td>
            <td>{{.Hostname}}</td>
            <td>{{.Port}}</td>
            <td>{{.Weight}}</td>
            <td><span class="node-status {{.Status}}">{{.Status}}</span></td>
            <td>{{.MaxConns}}</td>
            <td style="font-size:0.72rem">{{.Source}}</td>
            <td>{{.LineNum}}</td>
          </tr>
          {{else}}
          <tr><td colspan="10" class="empty">No backend nodes detected in log dumps.</td></tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Errors -->
  <div id="errors" class="panel">
    <div class="card">
      <div class="card-header" style="color:var(--error)">Errors ({{len .Errors}})<span class="tag" style="background:rgba(255,77,79,0.15);color:var(--error)">Critical</span></div>
      {{range .Errors}}
      <div class="alert-card error-alert" data-search="{{lower .Timestamp}} {{lower .Source}} {{lower .Message}} error" data-ts="{{.Timestamp}}">
        <div class="alert-head">
          <div class="alert-icon">✕</div>
          <span class="badge badge-ERROR">ERROR</span>
          <span class="ts">{{.Timestamp}}</span>
          <span class="line-num">Line {{.LineNum}}</span>
        </div>
        <div class="alert-msg">{{.Message}}</div>
        {{if .Source}}<div class="alert-meta">{{.Source}}</div>{{end}}
      </div>
      {{else}}
      <div class="empty">No errors found in this log file.</div>
      {{end}}
    </div>
  </div>

  <!-- Warnings -->
  <div id="warnings" class="panel">
    <div class="card">
      <div class="card-header" style="color:var(--warn)">Warnings ({{len .Warnings}})<span class="tag" style="background:rgba(245,166,35,0.15);color:var(--warn)">Review</span></div>
      {{range .Warnings}}
      <div class="alert-card warn-alert" data-search="{{lower .Timestamp}} {{lower .Source}} {{lower .Message}} warning" data-ts="{{.Timestamp}}">
        <div class="alert-head">
          <div class="alert-icon">!</div>
          <span class="badge badge-WARNING">WARNING</span>
          <span class="ts">{{.Timestamp}}</span>
          <span class="line-num">Line {{.LineNum}}</span>
        </div>
        <div class="alert-msg">{{.Message}}</div>
        {{if .Source}}<div class="alert-meta">{{.Source}}</div>{{end}}
      </div>
      {{else}}
      <div class="empty">No warnings found in this log file.</div>
      {{end}}
    </div>
  </div>

  <!-- Node Dumps (Tables) -->
  <div id="dumps" class="panel">
    {{range $i, $t := .Tables}}
    <div class="card dump-card" data-search="{{lower $t.Title}} {{lower $t.Engine}} {{lower $t.Kind}} {{lower $t.Timestamp}} {{$t.LineStart}}" data-ts="{{$t.Timestamp}}">
      <div class="card-header">
        {{if $t.Title}}{{$t.Title}}{{else}}Dump {{add $i 1}}{{end}}
        <span>
          {{if $t.Timestamp}}<span class="ts" style="margin-right:0.5rem">{{$t.Timestamp}}</span>{{end}}
          <span class="engine-tag">{{$t.Engine}}</span>
          <span class="tag" style="background:var(--surface3);color:var(--muted);margin-left:0.3rem">{{$t.Kind}} &middot; {{len $t.Rows}} rows &middot; L{{$t.LineStart}}</span>
        </span>
      </div>
      {{if $t.Rows}}
      <div style="overflow-x:auto">
        <table class="data">
          <thead><tr>{{range $t.Headers}}<th>{{.}}</th>{{end}}</tr></thead>
          <tbody>{{range $t.Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</tbody>
        </table>
      </div>
      {{else}}
      <div class="empty" style="padding:1rem">Empty table — no backend nodes configured at this point.</div>
      {{end}}
    </div>
    {{else}}
    <div class="card"><div class="empty">No server dump tables found.</div></div>
    {{end}}
  </div>

  <!-- Full Log -->
  <div id="logs" class="panel">
    <div class="toolbar">
      <select id="level-filter">
        <option value="">All levels</option>
        <option value="INFO">INFO</option>
        <option value="WARNING">WARNING</option>
        <option value="ERROR">ERROR</option>
        <option value="OTHER">OTHER</option>
      </select>
      <select id="cat-filter">
        <option value="">All categories</option>
        <option value="startup">Startup</option>
        <option value="config_change">Config Changes</option>
        <option value="backend_nodes">Backend Nodes</option>
        <option value="monitor">Monitor</option>
        <option value="warning">Warning</option>
        <option value="error">Error</option>
        <option value="component">Component</option>
        <option value="general">General</option>
      </select>
    </div>
    <div class="card">
      <div class="log-list" id="log-list">
      {{range .Entries}}{{if ne .Kind "blank"}}
      <div class="log-row" data-level="{{.Level}}" data-cat="{{.Category}}" data-ts="{{.Timestamp}}"
           data-search="{{lower .Timestamp}} {{lower .Level}} {{lower .Source}} {{lower .Message}} {{lower .Category}} line {{.LineNum}}">
        <span class="line-num">{{.LineNum}}</span>
        <span class="ts">{{.Timestamp}}</span>
        <span><span class="badge badge-{{.Level}}">{{.Level}}</span></span>
        <span><span class="cat-badge">{{.Category}}</span></span>
        <span class="msg">{{if .Source}}<span class="src">{{.Source}}</span>{{end}}<span class="msg-text">{{.Message}}</span></span>
      </div>
      {{end}}{{end}}
      </div>
    </div>
  </div>
</div>

<script>
const globalSearch = document.getElementById('global-search');
const searchCount = document.getElementById('search-count');
const levelFilter = document.getElementById('level-filter');
const catFilter = document.getElementById('cat-filter');
const dateFrom = document.getElementById('date-from');
const dateTo = document.getElementById('date-to');
const clearFiltersBtn = document.getElementById('clear-filters');
let nodeStatusFilter = '';
let nodeHGFilter = '';
let timelineHGFilter = '';
let timelineStatusFilter = '';

function searchableItems() {
  return document.querySelectorAll('[data-search]');
}

// Log timestamps are "YYYY-MM-DD HH:MM:SS". datetime-local inputs give
// "YYYY-MM-DDTHH:MM" or "...:SS". Normalizing both to the same "T"
// separator and zero-padding lets us compare them as plain strings.
function normalizeTs(ts) {
  if (!ts) return '';
  let s = ts.replace(' ', 'T');
  if (s.length === 16) s += ':00'; // no seconds supplied
  return s;
}

function tsInRange(ts) {
  const from = dateFrom.value, to = dateTo.value;
  if (!from && !to) return true;
  if (!ts) return false; // items with no timestamp can't be placed in a range
  const t = normalizeTs(ts);
  if (from && t < normalizeTs(from)) return false;
  if (to && t > normalizeTs(to)) return false;
  return true;
}

function hasActiveFilters() {
  return !!(globalSearch.value.trim() || dateFrom.value || dateTo.value || nodeStatusFilter ||
    timelineHGFilter || timelineStatusFilter ||
    (levelFilter && levelFilter.value) || (catFilter && catFilter.value));
}

function applyGlobalSearch() {
  const q = (globalSearch.value || '').trim().toLowerCase();
  const rangeActive = !!(dateFrom.value || dateTo.value);

  searchableItems().forEach(el => {
    const text = el.dataset.search || '';
    const matchQ = !q || text.includes(q);
    const matchDate = tsInRange(el.dataset.ts);
    // data-status/data-hg are only present on backend-node rows; elements
    // without them (every other tab) are unaffected by these filters.
    const matchStatus = !nodeStatusFilter || el.dataset.status === undefined || el.dataset.status === nodeStatusFilter;
    const matchHG = !nodeHGFilter || el.dataset.hg === undefined || el.dataset.hg === nodeHGFilter;
    const match = matchQ && matchDate && matchStatus && matchHG;
    el.classList.toggle('hidden', !match);
  });

  // Also filter log rows with level/cat when on logs panel
  const lvl = levelFilter ? levelFilter.value : '';
  const cat = catFilter ? catFilter.value : '';
  document.querySelectorAll('#log-list .log-row').forEach(row => {
    const matchL = !lvl || row.dataset.level === lvl;
    const matchC = !cat || row.dataset.cat === cat;
    const matchQ = !q || (row.dataset.search || '').includes(q);
    const matchDate = tsInRange(row.dataset.ts);
    const show = matchQ && matchL && matchC && matchDate;
    row.classList.toggle('hidden', !show);
  });

  // Event Timeline tab: filter by hostgroup/HID and status on top of the
  // search+date match already applied above (most events have no HG/status,
  // so the filter simply doesn't apply to them).
  let timelineVisible = 0, timelineTotal = 0;
  document.querySelectorAll('#event-timeline .tl-item').forEach(item => {
    timelineTotal++;
    const matchQ = !q || (item.dataset.search || '').includes(q);
    const matchDate = tsInRange(item.dataset.ts);
    const matchHG = !timelineHGFilter || item.dataset.tlHg === timelineHGFilter;
    const matchStatus = !timelineStatusFilter || item.dataset.tlStatus === timelineStatusFilter;
    const show = matchQ && matchDate && matchHG && matchStatus;
    item.classList.toggle('hidden', !show);
    if (show) timelineVisible++;
  });
  const timelineEmptyMsg = document.getElementById('timeline-empty-filtered');
  if (timelineEmptyMsg) {
    timelineEmptyMsg.style.display = (timelineTotal > 0 && timelineVisible === 0) ? 'block' : 'none';
  }

  const visible = document.querySelectorAll('[data-search]:not(.hidden)').length;

  if (q || rangeActive) {
    searchCount.textContent = visible + ' match' + (visible !== 1 ? 'es' : '');
  } else {
    searchCount.textContent = '';
  }
  if (q) {
    highlightMatches(q);
  } else {
    clearHighlights();
  }
}

function highlightMatches(q) {
  document.querySelectorAll('.msg-text').forEach(el => {
    const text = el.textContent;
    const idx = text.toLowerCase().indexOf(q);
    if (idx >= 0) {
      el.innerHTML = text.substring(0, idx) + '<mark>' + text.substring(idx, idx + q.length) + '</mark>' + text.substring(idx + q.length);
    }
  });
}

function clearHighlights() {
  document.querySelectorAll('.msg-text').forEach(el => {
    el.innerHTML = el.textContent;
  });
}

function clearAllFilters() {
  globalSearch.value = '';
  dateFrom.value = '';
  dateTo.value = '';
  if (levelFilter) levelFilter.value = '';
  if (catFilter) catFilter.value = '';
  nodeStatusFilter = '';
  nodeHGFilter = '';
  timelineHGFilter = '';
  timelineStatusFilter = '';
  document.querySelectorAll('#status-filter-row .status-chip').forEach(c => c.classList.toggle('active', c.dataset.status === ''));
  document.querySelectorAll('#timeline-filter-row .status-chip').forEach(c => c.classList.toggle('active', c.dataset.tlStatus === ''));
  const hgSelect = document.getElementById('timeline-hg-filter');
  if (hgSelect) hgSelect.value = '';
  const nodeHgSelect = document.getElementById('node-hg-filter');
  if (nodeHgSelect) nodeHgSelect.value = '';
  applyGlobalSearch();
}

document.querySelectorAll('#status-filter-row .status-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    nodeStatusFilter = chip.dataset.status;
    document.querySelectorAll('#status-filter-row .status-chip').forEach(c => c.classList.toggle('active', c === chip));
    applyGlobalSearch();
  });
});

document.querySelectorAll('#timeline-filter-row .status-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    timelineStatusFilter = chip.dataset.tlStatus;
    document.querySelectorAll('#timeline-filter-row .status-chip').forEach(c => c.classList.toggle('active', c === chip));
    applyGlobalSearch();
  });
});
const timelineHGSelect = document.getElementById('timeline-hg-filter');
if (timelineHGSelect) {
  timelineHGSelect.addEventListener('change', () => {
    timelineHGFilter = timelineHGSelect.value;
    applyGlobalSearch();
  });
}
const nodeHGSelect = document.getElementById('node-hg-filter');
if (nodeHGSelect) {
  nodeHGSelect.addEventListener('change', () => {
    nodeHGFilter = nodeHGSelect.value;
    applyGlobalSearch();
  });
}

globalSearch.addEventListener('input', applyGlobalSearch);
dateFrom.addEventListener('change', applyGlobalSearch);
dateTo.addEventListener('change', applyGlobalSearch);
if (levelFilter) levelFilter.addEventListener('change', applyGlobalSearch);
if (catFilter) catFilter.addEventListener('change', applyGlobalSearch);
if (clearFiltersBtn) clearFiltersBtn.addEventListener('click', clearAllFilters);

document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== globalSearch) {
    e.preventDefault();
    globalSearch.focus();
  }
});
</script>
</body>
</html>`

type pageData struct {
	*Analysis
}

func main() {
	logPath := flag.String("file", "proxysql.log", "path to proxysql.log")
	port := flag.String("port", "8080", "HTTP listen port")
	flag.Parse()

	var err error
	analysis, err = parseLog(*logPath)
	if err != nil {
		log.Fatalf("failed to parse %s: %v", *logPath, err)
	}

	funcMap := template.FuncMap{
		"add":   func(a, b int) int { return a + b },
		"lower": func(s string) string { return strings.ToLower(s) },
	}

	tmpl, err := template.New("page").Funcs(funcMap).Parse(pageHTML)
	if err != nil {
		log.Fatalf("template error: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, pageData{Analysis: analysis}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/api/analysis", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(analysis)
	})

	addr := ":" + strings.TrimPrefix(*port, ":")

	fmt.Printf("ProxySQL Log Analyzer\n")
	fmt.Printf("  File:    %s (%d lines)\n", analysis.File, analysis.TotalLines)
	if analysis.Meta.Version != "" {
		fmt.Printf("  Version: %s\n", analysis.Meta.Version)
	}
	fmt.Printf("  Levels:  INFO=%d  WARNING=%d  ERROR=%d\n",
		analysis.LevelCounts["INFO"], analysis.LevelCounts["WARNING"], analysis.LevelCounts["ERROR"])
	fmt.Printf("  Config:  %d LOAD/SAVE events\n", len(analysis.ConfigEvents))
	fmt.Printf("  Nodes:   %d backend node entries\n", len(analysis.BackendNodes))
	fmt.Printf("  Open:    http://localhost%s\n", addr)
	fmt.Printf("  API:     http://localhost%s/api/analysis\n", addr)

	log.Fatal(http.ListenAndServe(addr, nil))
}
