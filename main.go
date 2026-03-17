package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ─── ANSI COLOR PALETTE ───────────────────────────────────────────────────────

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Italic = "\033[3m"

	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"

	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"
)

func Fg256(code int) string { return fmt.Sprintf("\033[38;5;%dm", code) }
func Bg256(code int) string { return fmt.Sprintf("\033[48;5;%dm", code) }

// ─── TYPES ────────────────────────────────────────────────────────────────────

type PortState string

const (
	StateOpen     PortState = "open"
	StateFiltered PortState = "filtered"
	StateClosed   PortState = "closed"
)

type ScriptOutput struct {
	Name  string
	Lines []string
}

type Port struct {
	Number   int
	Protocol string
	State    PortState
	Service  string
	Version  string
	Scripts  []ScriptOutput
}

type TracerouteHop struct {
	Hop      int
	RTT      string
	IP       string
	Hostname string
}

type OSGuess struct {
	Name     string
	Accuracy int
	CPE      []string
}

type Host struct {
	IP          string
	Hostname    string
	Status      string
	Ports       []Port
	OS          string
	OSGuesses   []OSGuess
	CPE         []string
	HostScripts []ScriptOutput
	Traceroute  []TracerouteHop
	Latency     string
	MAC         string
	MACVendor   string
}

type ScanResult struct {
	Hosts       []Host
	StartTime   time.Time
	ElapsedSecs float64
	RawLines    []string
}

// ─── REGEX PATTERNS ───────────────────────────────────────────────────────────

var (
	reNmapStart       = regexp.MustCompile(`Starting Nmap (\S+)`)
	reHost            = regexp.MustCompile(`Nmap scan report for (.+)`)
	reHostStatus      = regexp.MustCompile(`Host is (up|down)(?:\s+\((.+?) latency\))?`)
	rePort            = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)(?:\s+(.+))?$`)
	reOS              = regexp.MustCompile(`^OS details: (.+)`)
	reOSGuess         = regexp.MustCompile(`^Aggressive OS guesses: (.+)`)
	reOSGuessItem     = regexp.MustCompile(`(.+?)\s+\((\d+)%\)`)
	reCPE             = regexp.MustCompile(`^\s+cpe:/(.+)`)
	reMAC             = regexp.MustCompile(`MAC Address: ([0-9A-F:]+)(?: \((.+)\))?`)
	reScanDone        = regexp.MustCompile(`Nmap done.*?(\d+) IP.*?scanned in ([\d.]+) seconds`)
	rePercentage      = regexp.MustCompile(`(\d+\.\d+)% done`)
	reScriptHeader    = regexp.MustCompile(`^\| ([^:]+):$`)
	reScriptContLine  = regexp.MustCompile(`^\|   (.*)`)
	reScriptFinalLine = regexp.MustCompile(`^\|_  (.*)`)
	reScriptInline    = regexp.MustCompile(`^\|_([^_].*)`)
	reScriptOpenKV    = regexp.MustCompile(`^\| (.+)`)
	reHostScriptLabel = regexp.MustCompile(`^Host script results:`)
	reTracerouteHdr   = regexp.MustCompile(`^TRACEROUTE`)
	reTracerouteHop   = regexp.MustCompile(`^\s*(\d+)\s+([\d.]+\s+ms|\.\.\.)\s+(.+)`)
)

// ─── TERMINAL HELPERS ─────────────────────────────────────────────────────────

func termWidth() int {
	if c := os.Getenv("COLUMNS"); c != "" {
		if w, err := strconv.Atoi(strings.TrimSpace(c)); err == nil && w > 40 {
			return w
		}
	}
	tty, err := os.Open("/dev/tty")
	if err == nil {
		defer tty.Close()
		cmd := exec.Command("tput", "cols")
		cmd.Stdin = tty
		if out, err2 := cmd.Output(); err2 == nil {
			if w, err3 := strconv.Atoi(strings.TrimSpace(string(out))); err3 == nil && w > 40 {
				return w
			}
		}
	}
	return 110
}

func clearScreen() { fmt.Print("\033[2J\033[H") }

var reANSI = regexp.MustCompile(`\033\[[0-9;]*[mABCDHJKfsu]`)

func visibleLen(s string) int {
	return utf8.RuneCountInString(reANSI.ReplaceAllString(s, ""))
}

func padRight(s string, width int) string {
	v := visibleLen(s)
	if v >= width {
		return s
	}
	return s + strings.Repeat(" ", width-v)
}

func clipToVisible(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

func rep(ch string, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(ch, n)
}

// ─── BANNER ───────────────────────────────────────────────────────────────────
func runShuttle(stop <-chan struct{}, width int) {
	track := width - 14
	if track < 10 {
		track = 10
	}
	shuttle := []rune("◀▬▬▶")
	slen := len(shuttle)
	pos, dir := 0, 1

	colors := []int{196, 202, 208, 214, 220, 226, 220, 214, 208, 202}
	tick := 0

	for {
		select {
		case <-stop:
			fmt.Print("\r\033[2K")
			return
		default:
			c := colors[tick%len(colors)]
			left := strings.Repeat("·", pos)
			right := strings.Repeat("·", track-pos-slen)
			fmt.Printf("\r  %s %s%s%s%s%s ",
				Fg256(238)+"["+Reset,
				Fg256(238), left,
				Fg256(c)+Bold+string(shuttle)+Reset,
				Fg256(238), right+"]",
			)
			pos += dir
			if pos+slen >= track || pos <= 0 {
				dir *= -1
			}
			tick++
			time.Sleep(40 * time.Millisecond)
		}
	}
}

func printBanner(width int) {
	lines := []string{
		Fg256(196) + `  ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ` + Reset,
		Fg256(202) + `  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗` + Reset,
		Fg256(214) + `  ██╔██╗ ██║██╔████╔██║███████║██████╔╝` + Reset,
		Fg256(220) + `  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ` + Reset,
		Fg256(226) + `  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ` + Reset,
		Fg256(229) + `  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ` + Reset,
	}
	fmt.Println()
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Println(Fg256(245) + Italic + "  Breathtaking NMAP Output Parser" + Reset)
	fmt.Println(Fg256(239) + "  v2.0.0  ·  " + Fg256(33) + "github.com/sandipduley/G-nmap-parser" + Reset)
	printHRule(width, Fg256(238))
	fmt.Println()
}

func printHRule(width int, color string) {
	fmt.Println(color + rep("─", width) + Reset)
}

// ─── COLORING ─────────────────────────────────────────────────────────────────

var dangerousPorts = map[int]bool{
	21: true, 23: true, 445: true, 3389: true,
	5900: true, 6379: true, 27017: true, 11211: true,
	512: true, 513: true, 514: true, 1099: true, 2049: true,
}

func portStateIcon(state PortState) string {
	switch state {
	case StateOpen:
		return BrightGreen + "●" + Reset
	case StateFiltered:
		return BrightYellow + "◐" + Reset
	case StateClosed:
		return Fg256(240) + "○" + Reset
	default:
		return "?"
	}
}

func portStateColor(state PortState) string {
	switch state {
	case StateOpen:
		return BrightGreen
	case StateFiltered:
		return BrightYellow
	case StateClosed:
		return Fg256(240)
	default:
		return White
	}
}

func serviceColor(portNum int, service string) string {
	if dangerousPorts[portNum] {
		return BrightRed + Bold
	}
	s := strings.ToLower(service)
	switch {
	case strings.Contains(s, "http"):
		return BrightCyan
	case strings.Contains(s, "ssh"):
		return BrightGreen
	case strings.Contains(s, "ftp"):
		return BrightYellow
	case strings.Contains(s, "smtp") || strings.Contains(s, "imap") || strings.Contains(s, "pop"):
		return Fg256(213)
	case strings.Contains(s, "sql") || strings.Contains(s, "mongo") ||
		strings.Contains(s, "redis") || strings.Contains(s, "postgres"):
		return Fg256(208)
	default:
		return White
	}
}

func scriptKeyColor(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "vuln") || strings.Contains(n, "exploit"):
		return BrightRed + Bold
	case strings.Contains(n, "ssl") || strings.Contains(n, "tls") || strings.Contains(n, "cert"):
		return Fg256(117)
	case strings.Contains(n, "http"):
		return BrightCyan
	case strings.Contains(n, "ssh"):
		return BrightGreen
	case strings.Contains(n, "smb") || strings.Contains(n, "ms"):
		return Fg256(208)
	default:
		return Fg256(183)
	}
}

// ─── CARD PRIMITIVES ──────────────────────────────────────────────────────────

func cardInnerWidth(width int) int { return width - 4 }

// cardLine prints one line inside the box, padding or hard-clipping to fit.
func cardLine(inner string, width int) {
	cw := cardInnerWidth(width)
	vl := visibleLen(inner)
	var content string
	if vl > cw {
		plain := reANSI.ReplaceAllString(inner, "")
		runes := []rune(plain)
		if len(runes) > cw {
			plain = string(runes[:cw-1]) + "…"
		}
		content = Fg256(244) + plain + Reset
	} else {
		content = inner + strings.Repeat(" ", cw-vl)
	}
	fmt.Print(Fg256(27) + "│ " + Reset + content + Fg256(27) + " │" + Reset + "\n")
}

// cardBlank prints an empty line inside the box — used to space ports apart.
func cardBlank(width int) {
	cw := cardInnerWidth(width)
	fmt.Print(Fg256(27) + "│ " + Reset + strings.Repeat(" ", cw) + Fg256(27) + " │" + Reset + "\n")
}

func cardSep(width int) {
	fmt.Print(Fg256(27) + "│ " + Fg256(236) + rep("─", cardInnerWidth(width)) + Fg256(27) + " │" + Reset + "\n")
}

func wrapPlain(s string, maxWidth int) []string {
	if maxWidth < 10 {
		maxWidth = 10
	}
	runes := []rune(s)
	if len(runes) <= maxWidth {
		return []string{s}
	}
	var out []string
	for len(runes) > maxWidth {
		out = append(out, string(runes[:maxWidth]))
		runes = runes[maxWidth:]
	}
	if len(runes) > 0 {
		out = append(out, string(runes))
	}
	return out
}

func renderScript(sc ScriptOutput, width int, indent string) {
	cw := cardInnerWidth(width)
	nameColor := scriptKeyColor(sc.Name)

	if len(sc.Lines) == 0 {
		cardLine(indent+"  "+nameColor+"▸ "+sc.Name+Reset, width)
		return
	}
	if len(sc.Lines) == 1 {
		prefix := indent + "  " + nameColor + "▸ " + sc.Name + Reset + ":  "
		prefixLen := visibleLen(prefix)
		val := sc.Lines[0]
		if prefixLen+len([]rune(val)) <= cw {
			cardLine(prefix+Fg256(252)+val+Reset, width)
			return
		}
		cardLine(prefix, width)
		for _, chunk := range wrapPlain(val, cw-4) {
			cardLine(indent+"      "+Fg256(246)+chunk+Reset, width)
		}
		return
	}
	cardLine(indent+"  "+nameColor+"▸ "+sc.Name+Reset+":", width)
	for _, l := range sc.Lines {
		for _, chunk := range wrapPlain(l, cw-len([]rune(indent))-6) {
			cardLine(indent+"      "+Fg256(246)+chunk+Reset, width)
		}
	}
}

// ─── HOST CARD ────────────────────────────────────────────────────────────────

func renderHostCard(h Host, width int) {
	fmt.Print(Fg256(27) + "╭" + rep("─", width-2) + "╮" + Reset + "\n")

	// Header: IP / hostname / status / latency
	ipStr := Bold + BrightCyan + "⬡  " + h.IP + Reset
	if h.Hostname != "" && h.Hostname != h.IP {
		ipStr += "  " + Dim + "(" + h.Hostname + ")" + Reset
	}
	status := BrightGreen + "▲ UP" + Reset
	if h.Status != "up" {
		status = BrightRed + "▼ DOWN" + Reset
	}
	lat := ""
	if h.Latency != "" {
		lat = "  " + Fg256(244) + "⟳ " + h.Latency + Reset
	}
	cardLine(ipStr+"  "+status+lat, width)

	if h.MAC != "" {
		mac := Fg256(245) + "  MAC: " + Fg256(252) + h.MAC
		if h.MACVendor != "" {
			mac += "  " + Fg256(244) + "(" + h.MACVendor + ")"
		}
		cardLine(mac+Reset, width)
	}
	if h.OS != "" {
		cardLine(Fg256(245)+"  OS: "+Italic+Fg256(252)+h.OS+Reset, width)
	}

	// OS guesses
	if len(h.OSGuesses) > 0 {
		cardSep(width)
		cardLine(Bold+Fg256(220)+"  OS Guesses"+Reset, width)
		for _, g := range h.OSGuesses {
			accColor := BrightGreen
			if g.Accuracy < 90 {
				accColor = BrightYellow
			}
			if g.Accuracy < 75 {
				accColor = BrightRed
			}
			cardLine("    "+Fg256(252)+g.Name+Reset+"  "+accColor+Bold+fmt.Sprintf("%d%%", g.Accuracy)+Reset, width)
			for _, c := range g.CPE {
				cardLine("      "+Fg256(240)+"cpe:/"+c+Reset, width)
			}
		}
	} else if len(h.CPE) > 0 {
		for _, c := range h.CPE {
			cardLine("    "+Fg256(240)+"cpe:/"+c+Reset, width)
		}
	}

	// Ports
	if len(h.Ports) == 0 {
		cardSep(width)
		cardLine(Fg256(240)+Italic+"  No ports found."+Reset, width)
	} else {
		cw := cardInnerWidth(width)
		portCol := 8
		protoCol := 6
		stateCol := 12
		serviceCol := 18
		// 2 (icon+space) + portCol + 1 + protoCol + 1 + stateCol + 1 + serviceCol + 1 = fixed
		fixedTotal := 2 + portCol + 1 + protoCol + 1 + stateCol + 1 + serviceCol + 1
		verCol := cw - fixedTotal - 7 // 7 reserved for RISK badge
		if verCol < 12 {
			verCol = 12
		}

		cardSep(width)
		hdr := "  " +
			padRight("PORT", portCol) + " " +
			padRight("PROTO", protoCol) + " " +
			padRight("STATE", stateCol) + " " +
			padRight("SERVICE", serviceCol) + " " +
			"VERSION"
		cardLine(Bold+Fg256(245)+hdr+Reset, width)
		cardSep(width)

		for i := range h.Ports {
			p := &h.Ports[i]

			pnColor := Fg256(33)
			if dangerousPorts[p.Number] {
				pnColor = BrightRed
			}
			badge := ""
			badgeVisible := 0
			if dangerousPorts[p.Number] {
				badge = " " + Bg256(196) + Black + Bold + " RISK " + Reset
				badgeVisible = 7
			}
			ver := clipToVisible(p.Version, verCol-badgeVisible)
			verStr := Fg256(244) + ver + Reset
			if p.Version == "" {
				verStr = Fg256(238) + "—" + Reset
			}

			row := portStateIcon(p.State) + " " +
				padRight(pnColor+Bold+fmt.Sprintf("%d", p.Number)+Reset, portCol) + " " +
				padRight(Fg256(246)+p.Protocol+Reset, protoCol) + " " +
				padRight(portStateColor(p.State)+string(p.State)+Reset, stateCol) + " " +
				padRight(serviceColor(p.Number, p.Service)+p.Service+Reset, serviceCol) + " " +
				verStr + badge
			cardLine(row, width)

			// NSE scripts indented under the port
			for _, sc := range p.Scripts {
				renderScript(sc, width, "  ")
			}

			// Blank separator line between ports (but not after the last one)
			if i < len(h.Ports)-1 {
				cardBlank(width)
			}
		}

		openCount := 0
		for _, p := range h.Ports {
			if p.State == StateOpen {
				openCount++
			}
		}
		cardSep(width)
		cardLine(Fg256(240)+fmt.Sprintf("  %d port(s) shown", len(h.Ports))+"  ·  "+BrightGreen+fmt.Sprintf("%d open", openCount)+Reset, width)
	}

	// Host-level scripts
	if len(h.HostScripts) > 0 {
		cardSep(width)
		cardLine(Bold+Fg256(220)+"  Host Scripts"+Reset, width)
		for _, sc := range h.HostScripts {
			renderScript(sc, width, "  ")
		}
	}

	// Traceroute
	if len(h.Traceroute) > 0 {
		cardSep(width)
		cardLine(Bold+Fg256(69)+"  Traceroute"+Reset, width)
		cardLine(Fg256(238)+
			padRight("    HOP", 10)+
			padRight("RTT", 16)+
			padRight("ADDRESS", 22)+
			"HOSTNAME"+Reset, width)
		for _, hop := range h.Traceroute {
			hopStr := Fg256(244) + fmt.Sprintf("    %2d", hop.Hop) + Reset
			rttStr := BrightYellow + hop.RTT + Reset
			if hop.RTT == "..." {
				rttStr = Fg256(240) + "  * * *" + Reset
			}
			hn := ""
			if hop.Hostname != "" && hop.Hostname != hop.IP {
				hn = Fg256(244) + "  " + hop.Hostname + Reset
			}
			cardLine(padRight(hopStr, 10)+padRight(rttStr, 16)+padRight(Fg256(39)+hop.IP+Reset, 22)+hn, width)
		}
	}

	fmt.Print(Fg256(27) + "╰" + rep("─", width-2) + "╯" + Reset + "\n\n")
}

// ─── SUMMARY / RISK ───────────────────────────────────────────────────────────

func renderSummary(result *ScanResult, width int) {
	printHRule(width, Fg256(238))
	fmt.Printf("\n%s  SCAN SUMMARY%s\n\n", Bold+Fg256(214), Reset)
	total, open, filtered, up, scripts := 0, 0, 0, 0, 0
	for _, h := range result.Hosts {
		if h.Status == "up" {
			up++
		}
		scripts += len(h.HostScripts)
		for _, p := range h.Ports {
			total++
			scripts += len(p.Scripts)
			switch p.State {
			case StateOpen:
				open++
			case StateFiltered:
				filtered++
			}
		}
	}
	for _, r := range []struct{ l, v, c string }{
		{"Hosts scanned", fmt.Sprintf("%d", len(result.Hosts)), BrightCyan},
		{"Hosts up", fmt.Sprintf("%d", up), BrightGreen},
		{"Ports found", fmt.Sprintf("%d", total), BrightWhite},
		{"Open", fmt.Sprintf("%d", open), BrightGreen},
		{"Filtered", fmt.Sprintf("%d", filtered), BrightYellow},
		{"Script results", fmt.Sprintf("%d", scripts), Fg256(183)},
		{"Elapsed", fmt.Sprintf("%.2fs", result.ElapsedSecs), Fg256(244)},
	} {
		fmt.Printf("  %s%-18s%s%s%s%s\n", Fg256(240), r.l, Reset, r.c+Bold, r.v, Reset)
	}
	fmt.Println()
	printHRule(width, Fg256(238))
	fmt.Println()
}

func renderRiskHighlights(result *ScanResult, width int) {
	fmt.Printf("%s  ⚠  RISK HIGHLIGHTS%s\n\n", Bold+BrightRed, Reset)
	found := false
	for _, h := range result.Hosts {
		for _, p := range h.Ports {
			if dangerousPorts[p.Number] && p.State == StateOpen {
				fmt.Printf("  %s%-18s%s %s%d/%s%s  %s%s%s\n",
					BrightCyan, h.IP, Reset,
					BrightRed+Bold, p.Number, p.Protocol, Reset,
					BrightYellow, p.Service, Reset)
				found = true
			}
		}
	}
	if !found {
		fmt.Printf("  %sNo high-risk ports detected.%s\n", BrightGreen, Reset)
	}
	fmt.Println()
	printHRule(width, Fg256(238))
	fmt.Println()
}

// ─── PARSER ───────────────────────────────────────────────────────────────────

type parseCtx int

const (
	ctxNone parseCtx = iota
	ctxPort
	ctxHostScript
	ctxTraceroute
)

// Parser is a pure data parser — no terminal output.
type Parser struct {
	result        *ScanResult
	currentHost   *Host
	currentPort   *Port
	currentScript *ScriptOutput
	ctx           parseCtx
}

func NewParser() *Parser {
	return &Parser{result: &ScanResult{StartTime: time.Now()}}
}

func (p *Parser) flushScript() {
	if p.currentScript == nil {
		return
	}
	switch p.ctx {
	case ctxPort:
		if p.currentPort != nil {
			p.currentPort.Scripts = append(p.currentPort.Scripts, *p.currentScript)
		}
	case ctxHostScript:
		if p.currentHost != nil {
			p.currentHost.HostScripts = append(p.currentHost.HostScripts, *p.currentScript)
		}
	}
	p.currentScript = nil
}

func (p *Parser) flush() {
	p.flushScript()
	p.currentPort = nil
	p.ctx = ctxNone
	if p.currentHost != nil {
		p.result.Hosts = append(p.result.Hosts, *p.currentHost)
		p.currentHost = nil
	}
}

func (p *Parser) ParseLine(raw string) {
	line := strings.TrimRight(raw, "\r\n")
	p.result.RawLines = append(p.result.RawLines, line)

	// Swallow progress/stats lines — no display needed.
	if rePercentage.MatchString(line) {
		return
	}
	if strings.HasPrefix(line, "Stats:") {
		return
	}

	if reNmapStart.MatchString(line) {
		return
	}

	if m := reHost.FindStringSubmatch(line); m != nil {
		p.flush()
		hostStr := m[1]
		ip, hostname := hostStr, ""
		if idx := strings.Index(hostStr, " ("); idx != -1 {
			hostname = hostStr[:idx]
			ip = strings.Trim(hostStr[idx:], " ()")
		}
		p.currentHost = &Host{IP: ip, Hostname: hostname, Status: "up"}
		return
	}

	if m := reHostStatus.FindStringSubmatch(line); m != nil {
		if p.currentHost != nil {
			p.currentHost.Status = m[1]
			if m[2] != "" {
				p.currentHost.Latency = m[2]
			}
		}
		return
	}

	if m := reMAC.FindStringSubmatch(line); m != nil {
		if p.currentHost != nil {
			p.currentHost.MAC = m[1]
			if len(m) > 2 {
				p.currentHost.MACVendor = m[2]
			}
		}
		return
	}

	if m := rePort.FindStringSubmatch(line); m != nil {
		p.flushScript()
		p.ctx = ctxPort
		if p.currentHost == nil {
			p.currentHost = &Host{IP: "unknown", Status: "up"}
		}
		portNum, _ := strconv.Atoi(m[1])
		stateStr := m[3]
		if strings.Contains(stateStr, "open|filtered") {
			stateStr = "filtered"
		}
		port := Port{
			Number:   portNum,
			Protocol: m[2],
			State:    PortState(stateStr),
			Service:  m[4],
			Version:  strings.TrimSpace(m[5]),
		}
		p.currentHost.Ports = append(p.currentHost.Ports, port)
		p.currentPort = &p.currentHost.Ports[len(p.currentHost.Ports)-1]
		return
	}

	if m := reOS.FindStringSubmatch(line); m != nil {
		if p.currentHost != nil {
			p.currentHost.OS = m[1]
		}
		return
	}

	if m := reOSGuess.FindStringSubmatch(line); m != nil {
		if p.currentHost != nil {
			for _, part := range strings.Split(m[1], ", ") {
				if gm := reOSGuessItem.FindStringSubmatch(part); gm != nil {
					acc, _ := strconv.Atoi(gm[2])
					p.currentHost.OSGuesses = append(p.currentHost.OSGuesses, OSGuess{
						Name:     strings.TrimSpace(gm[1]),
						Accuracy: acc,
					})
				}
			}
		}
		return
	}

	if m := reCPE.FindStringSubmatch(line); m != nil {
		if p.currentHost != nil {
			cpeVal := strings.TrimSpace(m[1])
			if len(p.currentHost.OSGuesses) > 0 {
				last := &p.currentHost.OSGuesses[len(p.currentHost.OSGuesses)-1]
				last.CPE = append(last.CPE, cpeVal)
			} else {
				p.currentHost.CPE = append(p.currentHost.CPE, cpeVal)
			}
		}
		return
	}

	if reHostScriptLabel.MatchString(line) {
		p.flushScript()
		p.currentPort = nil
		p.ctx = ctxHostScript
		return
	}

	if reTracerouteHdr.MatchString(line) {
		p.flushScript()
		p.currentPort = nil
		p.ctx = ctxTraceroute
		return
	}

	if p.ctx == ctxTraceroute {
		if m := reTracerouteHop.FindStringSubmatch(line); m != nil && p.currentHost != nil {
			hop := TracerouteHop{}
			hop.Hop, _ = strconv.Atoi(strings.TrimSpace(m[1]))
			rtt := strings.TrimSpace(m[2])
			if rtt == "..." {
				hop.RTT = "..."
				hop.IP = "* * *"
			} else {
				hop.RTT = rtt
				parts := strings.Fields(strings.TrimSpace(m[3]))
				hop.IP = parts[0]
				if len(parts) > 1 {
					hop.Hostname = parts[1]
				}
			}
			p.currentHost.Traceroute = append(p.currentHost.Traceroute, hop)
			return
		}
		if strings.TrimSpace(line) == "" {
			p.ctx = ctxNone
		}
		return
	}

	trimmed := strings.TrimRight(line, " ")

	if m := reScriptHeader.FindStringSubmatch(trimmed); m != nil {
		p.flushScript()
		p.currentScript = &ScriptOutput{Name: strings.TrimSpace(m[1])}
		return
	}
	if m := reScriptContLine.FindStringSubmatch(trimmed); m != nil {
		if p.currentScript != nil {
			if val := strings.TrimSpace(m[1]); val != "" {
				p.currentScript.Lines = append(p.currentScript.Lines, val)
			}
		}
		return
	}
	if m := reScriptFinalLine.FindStringSubmatch(trimmed); m != nil {
		val := strings.TrimSpace(m[1])
		if p.currentScript != nil {
			if val != "" {
				p.currentScript.Lines = append(p.currentScript.Lines, val)
			}
			p.flushScript()
		} else if val != "" {
			sc := ScriptOutput{}
			if idx := strings.Index(val, ": "); idx != -1 {
				sc.Name = strings.TrimSpace(val[:idx])
				sc.Lines = []string{strings.TrimSpace(val[idx+2:])}
			} else {
				sc.Name = val
			}
			p.currentScript = &sc
			p.flushScript()
		}
		return
	}
	if m := reScriptInline.FindStringSubmatch(trimmed); m != nil {
		p.flushScript()
		content := strings.TrimSpace(m[1])
		sc := ScriptOutput{}
		if idx := strings.Index(content, ": "); idx != -1 {
			sc.Name = strings.TrimSpace(content[:idx])
			sc.Lines = []string{strings.TrimSpace(content[idx+2:])}
		} else {
			sc.Name = content
		}
		p.currentScript = &sc
		p.flushScript()
		return
	}
	if m := reScriptOpenKV.FindStringSubmatch(trimmed); m != nil {
		p.flushScript()
		content := strings.TrimSpace(m[1])
		sc := ScriptOutput{}
		if idx := strings.Index(content, ": "); idx != -1 {
			sc.Name = strings.TrimSpace(content[:idx])
			sc.Lines = []string{strings.TrimSpace(content[idx+2:])}
		} else {
			sc.Name = content
		}
		p.currentScript = &sc
		p.flushScript()
		return
	}

	if m := reScanDone.FindStringSubmatch(line); m != nil {
		p.flush()
		elapsed, _ := strconv.ParseFloat(m[2], 64)
		p.result.ElapsedSecs = elapsed
		return
	}

	if strings.TrimSpace(line) == "" {
		p.flushScript()
	}
}

func (p *Parser) Finalize() *ScanResult {
	p.flush()
	return p.result
}

// ─── REPORT ───────────────────────────────────────────────────────────────────

func renderFullReport(result *ScanResult, width int, title string) {
	fmt.Println()
	printHRule(width, Fg256(238))
	fmt.Printf("\n%s  ═══  %s  ═══%s\n\n", Bold+Fg256(214), title, Reset)
	for _, h := range result.Hosts {
		renderHostCard(h, width)
	}
	renderSummary(result, width)
	renderRiskHighlights(result, width)
}

// ─── STDIN MODE ───────────────────────────────────────────────────────────────

func runStdinMode(width int) {
	clearScreen()
	printBanner(width)
	fmt.Printf("  %s⟳  Waiting for nmap output…%s\n  %s(Brewing results... Like good coffee, it takes time.)%s\n\n",
		Fg256(244), Reset, Fg256(238), Reset)
	printHRule(width, Fg256(238))
	fmt.Println()

	parser := NewParser()
	stopShuttle := make(chan struct{})
	go runShuttle(stopShuttle, width)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		parser.ParseLine(scanner.Text())
	}

	close(stopShuttle)
	time.Sleep(60 * time.Millisecond)
	result := parser.Finalize()
	for i := range result.Hosts {
		sort.Slice(result.Hosts[i].Ports, func(a, b int) bool {
			return result.Hosts[i].Ports[a].Number < result.Hosts[i].Ports[b].Number
		})
	}
	renderFullReport(result, width, "FULL SCAN REPORT")
}

// ─── DEMO MODE ────────────────────────────────────────────────────────────────

func runDemoMode(width int) {
	clearScreen()
	printBanner(width)
	fmt.Println(Fg256(208) + Bold + "  ⚡  DEMO MODE" + Reset +
		Fg256(244) + " — simulating: " + BrightWhite + "sudo nmap -A 10.165.212.180" + Reset)
	fmt.Println()
	printHRule(width, Fg256(238))
	fmt.Println()

	fakeLines := []string{
		"Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-15 09:41 UTC",
		"Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan",
		"Service scan Timing: About 23.50% done; ETC: 09:42 (0:00:10 remaining)",
		"Nmap scan report for victim.hack (10.165.212.180)",
		"Host is up (0.0014s latency).",
		"MAC Address: 08:00:27:E7:98:1A (Oracle VirtualBox)",
		"21/tcp   open  ftp      vsftpd 2.3.4",
		"| ftp-syst:",
		"|   STAT:",
		"|   FTP server status:",
		"|     Connected to 10.165.212.36",
		"|     Logged in as ftp",
		"|     TYPE: ASCII",
		"|     No session bandwidth limit",
		"|     Session timeout in seconds is 300",
		"|     Control connection is plain text",
		"|     Data connections will be plain text",
		"|_    vsFTPd 2.3.4 - secure, fast, stable",
		"| ftp-anon: Anonymous FTP login allowed (FTP code 230)",
		"|_  drwxr-xr-x    2 0        0            4096 Jan 01 00:00 pub",
		"22/tcp   open  ssh      OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)",
		"| ssh-hostkey:",
		"|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)",
		"|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)",
		"23/tcp   open  telnet   Linux telnetd",
		"25/tcp   open  smtp     Postfix smtpd",
		"| smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN",
		"| sslv2:",
		"|   SSLv2 supported",
		"|   ciphers:",
		"|     SSL2_DES_192_EDE3_CBC_WITH_MD5",
		"|     SSL2_RC4_128_EXPORT40_WITH_MD5",
		"|_    SSL2_RC2_128_CBC_WITH_MD5",
		"80/tcp   open  http     Apache httpd 2.2.8 ((Ubuntu) DAV/2)",
		"|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2",
		"|_http-title: Metasploitable2 - Linux",
		"139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)",
		"445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)",
		"512/tcp  open  exec     netkit-rsh rexecd",
		"513/tcp  open  login    OpenBSD or Solaris rlogind",
		"514/tcp  open  shell    Netkit rshd",
		"3306/tcp open  mysql    MySQL 5.0.51a-3ubuntu5",
		"| mysql-info:",
		"|   Protocol: 10",
		"|   Version: 5.0.51a-3ubuntu5",
		"|_  Status: Autocommit",
		"5900/tcp open  vnc      VNC (protocol 3.3)",
		"|_vnc-info: ERROR: Script execution failed (use -d to debug)",
		"6000/tcp open  X11      (access denied)",
		"OS details: Linux 2.6.9 - 2.6.33",
		"Aggressive OS guesses: Linux 2.6.23 (96%), Linux 2.6.24 (94%), Linux 2.6.22 (91%), Linux 2.6.18 (85%)",
		"  cpe:/o:linux:linux_kernel:2.6",
		"TRACEROUTE (using port 80/tcp)",
		" 1   0.31 ms  10.165.212.180",
		"",
		"Host script results:",
		"|_clock-skew: mean: 2h00m00s, deviation: 2h49m43s, median: 0s",
		"| smb-security-mode:",
		"|   account_used: guest",
		"|   authentication_level: user",
		"|_  challenge_response: supported",
		"| nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>",
		"|_  NetBIOS MAC: 08:00:27:e7:98:1a (Oracle VirtualBox)",
		"Nmap done: 1 IP address (1 host up) scanned in 34.21 seconds",
	}

	parser := NewParser()
	stopShuttle := make(chan struct{})
	go runShuttle(stopShuttle, width)

	for _, line := range fakeLines {
		time.Sleep(35 * time.Millisecond) // simulate live arrival
		parser.ParseLine(line)
	}

	close(stopShuttle)
	time.Sleep(60 * time.Millisecond)
	result := parser.Finalize()
	for i := range result.Hosts {
		sort.Slice(result.Hosts[i].Ports, func(a, b int) bool {
			return result.Hosts[i].Ports[a].Number < result.Hosts[i].Ports[b].Number
		})
	}
	renderFullReport(result, width, "FULL SCAN REPORT  (-A)")
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

func main() {
	width := termWidth()
	if width > 160 {
		width = 140
	}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		runStdinMode(width)
	} else {
		runDemoMode(width)
	}
}
