// ============================================================
//
//	OEnvScan — .env / Environment Secret & Misconfig Scanner
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only) — OWL suite
//
//	Finds hardcoded credentials, provider tokens and insecure settings in
//	.env / config files, the process environment and other processes'
//	environments, then weighs them by context: git exposure, file
//	permissions, template files, secret reuse and .env ↔ .env.example drift.
//	v1.1 adds git-history scanning, a generic high-entropy rule,
//	baselines / .oenvscanignore and an opt-in --fix mode. Without --fix
//	nothing is modified; nothing is ever uploaded or validated online.
//
// ============================================================
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func kv(k, v string)   { fmt.Println("  " + col("│  ", CY) + col(pad(k+":", 16), DIM) + col(v, W)) }

const BANNER = `
 ██████╗ ███████╗███╗   ██╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔═══██╗██╔════╝████╗  ██║██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║█████╗  ██╔██╗ ██║██║   ██║███████╗██║     ███████║██╔██╗ ██║
██║   ██║██╔══╝  ██║╚██╗██║╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝███████╗██║ ╚████║ ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
`

const APPNAME = "OEnvScan"
const SUITE = "Owl Secrets Suite"
const TAGLINE = ".env / Environment Secret & Misconfig Scanner"
const SUBLINE = "Secrets · Entropy · Git History · Perms · Drift · Baseline · Fix"
const VERSION = "1.1"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	rule()
	fmt.Println("  " + col("⬡  "+s, B+CY))
	rule()
	fmt.Println()
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
func vlen(s string) int { return utf8.RuneCountInString(stripANSI(s)) }
func pad(s string, n int) string {
	if l := vlen(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

// trunc shortens s to n runes, keeping the tail (paths read best from the end).
func truncLeft(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 2 {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 2 {
		return s
	}
	return string(r[:n-1]) + "…"
}

// table prints an aligned table; cells may already carry colour codes.
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", CY))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), CY))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			if !strings.Contains(v, "\033[") {
				v = col(v, W)
			}
			rb.WriteString(pad(v, w[i]))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", CY))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ====================================================================
//  DOMAIN MODEL
// ====================================================================

const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"
	SevInfo     = "INFO"
)

var sevRank = map[string]int{SevCritical: 5, SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1}
var sevOrder = []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

func sevColor(s string) string {
	switch s {
	case SevCritical:
		return col(s, R+B)
	case SevHigh:
		return col(s, R)
	case SevMedium:
		return col(s, OR)
	case SevLow:
		return col(s, YLW)
	default:
		return col(s, CY)
	}
}

func maxSev(a, b string) string {
	if sevRank[b] > sevRank[a] {
		return b
	}
	return a
}

// Finding is one issue at one location. Evidence is always masked unless
// --show-secrets is given; the raw value never leaves the process.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Key      string `json:"key,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	// Fingerprint is stable across runs (no line number, no raw value):
	// rule + path + key + hash of the value. Baselines and ignore files use it.
	Fingerprint string `json:"fingerprint,omitempty"`
	secret      bool   // finding is about a credential value (drives git/perm context)
	vfp         string // hash of the raw secret value ("" when not a value finding)
}

type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Target     string         `json:"target"`
	Generated  string         `json:"generated"`
	Files      int            `json:"files_scanned"`
	Suppressed int            `json:"suppressed,omitempty"`
	Counts     map[string]int `json:"counts"`
	Score      int            `json:"score"`
	Grade      string         `json:"grade"`
	Findings   []Finding      `json:"findings"`
}

// ruleInfo documents every rule ID (catalog view + SARIF rules + fix text).
type ruleInfo struct {
	ID, Sev, Title, Fix string
}

var ruleCatalog = []ruleInfo{
	{"ENV-PRIVATE-KEY", SevCritical, "Private key material", "Move the key to a secrets manager / key file with 0600 perms and rotate it."},
	{"ENV-AWS-KEY", SevHigh, "AWS access key ID", "Deactivate the key in IAM, rotate, and prefer roles / SSO credentials."},
	{"ENV-AWS-SECRET", SevHigh, "AWS secret access key", "Rotate the IAM key pair; never store long-lived AWS keys in env files."},
	{"ENV-GITHUB-TOKEN", SevHigh, "GitHub token", "Revoke at github.com/settings/tokens and use fine-grained, short-lived tokens."},
	{"ENV-GITLAB-TOKEN", SevHigh, "GitLab personal access token", "Revoke the PAT and scope replacements narrowly."},
	{"ENV-SLACK-TOKEN", SevHigh, "Slack token", "Revoke the token in the Slack app config."},
	{"ENV-SLACK-WEBHOOK", SevMedium, "Slack incoming webhook", "Regenerate the webhook URL; anyone holding it can post to the channel."},
	{"ENV-DISCORD-WEBHOOK", SevMedium, "Discord webhook", "Delete and recreate the webhook."},
	{"ENV-STRIPE-LIVE", SevCritical, "Stripe live secret key", "Roll the key in the Stripe dashboard immediately; use restricted keys."},
	{"ENV-STRIPE-TEST", SevLow, "Stripe test key", "Test keys cannot move money but still expose test data; keep out of VCS."},
	{"ENV-GOOGLE-KEY", SevHigh, "Google API key", "Restrict the key (API + referrer/IP) or regenerate it."},
	{"ENV-ANTHROPIC-KEY", SevHigh, "Anthropic API key", "Revoke the key in the Anthropic console and issue a new one."},
	{"ENV-OPENAI-KEY", SevHigh, "OpenAI API key", "Revoke the key in the OpenAI dashboard and issue a project-scoped one."},
	{"ENV-SENDGRID-KEY", SevHigh, "SendGrid API key", "Delete the key in SendGrid and create one with minimal scopes."},
	{"ENV-NPM-TOKEN", SevHigh, "npm access token", "Revoke with `npm token revoke` and use granular automation tokens."},
	{"ENV-PYPI-TOKEN", SevHigh, "PyPI upload token", "Revoke in PyPI account settings; prefer trusted publishing."},
	{"ENV-HF-TOKEN", SevMedium, "Hugging Face token", "Invalidate the token in Hugging Face settings."},
	{"ENV-DO-TOKEN", SevHigh, "DigitalOcean token", "Revoke the token in the DigitalOcean control panel."},
	{"ENV-SHOPIFY-TOKEN", SevHigh, "Shopify access token", "Rotate the app credentials."},
	{"ENV-TELEGRAM-TOKEN", SevMedium, "Telegram bot token", "Revoke via @BotFather (/revoke)."},
	{"ENV-TWILIO-KEY", SevMedium, "Twilio API key", "Delete the API key in the Twilio console."},
	{"ENV-MAILGUN-KEY", SevMedium, "Mailgun API key", "Rotate the Mailgun key."},
	{"ENV-AZURE-STORAGE", SevHigh, "Azure storage account key", "Rotate the storage account key; prefer SAS tokens or managed identity."},
	{"ENV-URL-CREDS", SevHigh, "Credentials embedded in a URL", "Split user/password into separate secrets injected at runtime."},
	{"ENV-JWT", SevMedium, "JSON Web Token", "Tokens grant access until they expire; do not persist them in config."},
	{"ENV-HARDCODED", SevMedium, "Hardcoded secret value", "Inject from a secrets manager / CI secret store; keep the file out of VCS."},
	{"ENV-LOW-ENTROPY", SevMedium, "Guessable secret value", "Replace with a random value (e.g. `openssl rand -base64 32`)."},
	{"ENV-SHORT", SevMedium, "Very short secret", "Use at least 16 random characters (32+ for signing keys)."},
	{"ENV-WEAK", SevHigh, "Weak / default secret", "Replace the default with a strong random value."},
	{"ENV-WEAK-LIST", SevLow, "Default-credential list", "Looks like a wordlist / vendor-default table; if any entry is a live account, change it."},
	{"ENV-EXAMPLE-SECRET", SevHigh, "Real-looking secret in a template file", "Template files are committed — replace with a placeholder and rotate the value."},
	{"ENV-PLACEHOLDER", SevInfo, "Placeholder / example credential", "Fine for templates; make sure production overrides it."},
	{"ENV-EMPTY", SevInfo, "Empty secret value", "Make sure the value is injected at runtime."},
	{"ENV-REUSE", SevMedium, "Same secret reused under different keys", "Use a distinct secret per purpose so one leak does not cascade."},
	{"ENV-DUP-KEY", SevLow, "Duplicate key", "Later definitions silently override earlier ones; keep one."},
	{"ENV-DEBUG", SevMedium, "Debug mode enabled", "Disable debug in production (stack traces, debug consoles, verbose errors)."},
	{"ENV-TLS-OFF", SevHigh, "TLS certificate verification disabled", "Re-enable verification; trust a private CA bundle instead of turning checks off."},
	{"ENV-CORS", SevMedium, "Wildcard CORS origin", "List explicit trusted origins."},
	{"ENV-HOSTS", SevMedium, "Wildcard allowed hosts", "List the real host names (Host-header attacks, cache poisoning)."},
	{"ENV-COOKIE", SevMedium, "Insecure session cookie flag", "Set Secure / HttpOnly on session cookies."},
	{"ENV-DB-SSL-OFF", SevLow, "Database connection without TLS", "Use sslmode=require / verify-full for remote databases."},
	{"ENV-PERM-WORLD", SevHigh, "Secrets file is world-readable", "chmod 600 the file."},
	{"ENV-PERM-GROUP", SevMedium, "Secrets file is group-readable", "chmod 600 (or 640 with a dedicated group)."},
	{"ENV-GIT-TRACKED", SevCritical, "Secrets file is committed to git", "git rm --cached the file, add it to .gitignore, and ROTATE every secret — history keeps them."},
	{"ENV-GIT-UNIGNORED", SevMedium, "Secrets file is not git-ignored", "Add the file to .gitignore before someone commits it."},
	{"ENV-DRIFT-MISSING", SevLow, "Key in template but missing from .env", "Add the key (or remove it from the template)."},
	{"ENV-DRIFT-UNDOC", SevLow, "Key in .env but not documented in template", "Add a placeholder for it to the template."},
	{"ENV-ENTROPY", SevMedium, "High-entropy value under a non-secret key", "If this is a credential, move it to a secrets manager; otherwise add its fingerprint to .oenvscanignore."},
	{"ENV-GIT-HISTORY", SevHigh, "Secret in git history", "Rotate the secret first, then purge it with git filter-repo / BFG and force-push — every existing clone still has it."},
}

var ruleByID = func() map[string]ruleInfo {
	m := map[string]ruleInfo{}
	for _, r := range ruleCatalog {
		m[r.ID] = r
	}
	return m
}()

// newFinding fills title/severity/fix from the catalog.
func newFinding(id, file string, line int, key, evidence, detail string) Finding {
	r := ruleByID[id]
	return Finding{RuleID: id, Severity: r.Sev, Title: r.Title, File: file, Line: line,
		Key: key, Evidence: evidence, Detail: detail, Fix: r.Fix}
}

// ====================================================================
//  SIGNATURES
// ====================================================================

type signature struct {
	id string
	re *regexp.Regexp
}

var signatures = []signature{
	{"ENV-PRIVATE-KEY", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"ENV-AWS-KEY", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"ENV-GITHUB-TOKEN", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`)},
	{"ENV-GITLAB-TOKEN", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`)},
	{"ENV-SLACK-TOKEN", regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z\-]{10,}`)},
	{"ENV-SLACK-WEBHOOK", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)},
	{"ENV-DISCORD-WEBHOOK", regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+`)},
	{"ENV-STRIPE-LIVE", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}`)},
	{"ENV-STRIPE-TEST", regexp.MustCompile(`\b[sr]k_test_[0-9A-Za-z]{20,}`)},
	{"ENV-GOOGLE-KEY", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`)},
	{"ENV-ANTHROPIC-KEY", regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}`)},
	{"ENV-OPENAI-KEY", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}`)},
	{"ENV-SENDGRID-KEY", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`)},
	{"ENV-NPM-TOKEN", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"ENV-PYPI-TOKEN", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`)},
	{"ENV-HF-TOKEN", regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,}\b`)},
	{"ENV-DO-TOKEN", regexp.MustCompile(`\bdo[pro]_v1_[a-f0-9]{64}\b`)},
	{"ENV-SHOPIFY-TOKEN", regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`)},
	{"ENV-TELEGRAM-TOKEN", regexp.MustCompile(`\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b`)},
	{"ENV-TWILIO-KEY", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`)},
	{"ENV-MAILGUN-KEY", regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`)},
	{"ENV-AZURE-STORAGE", regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{60,}`)},
	{"ENV-URL-CREDS", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s:/@'"]+:[^\s@/'"]+@[^\s/'"]+`)},
	{"ENV-JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)},
}

// rePEMBody: a PEM header followed by base64 key material (raw or JSON-escaped
// newlines). A bare header is usually a regex / detector string in code.
var rePEMBody = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:\s|\\n|\\r)*(?:Proc-Type|Version:|Comment:|[A-Za-z0-9+/=]{16,})`)

var reURLCreds = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*://)([^:/@]+):([^@/]+)@(.*)$`)

// ====================================================================
//  VALUE / KEY CLASSIFICATION
// ====================================================================

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var f [256]float64
	for i := 0; i < len(s); i++ {
		f[s[i]]++
	}
	e, n := 0.0, float64(len(s))
	for _, c := range f {
		if c > 0 {
			p := c / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// keyTokens upper-cases a key and splits it on separators and camelCase
// boundaries: "apiKey" → [API KEY], "//registry/:_authToken" → [REGISTRY AUTH TOKEN].
func keyTokens(k string) []string {
	var b strings.Builder
	rs := []rune(k)
	for i, r := range rs {
		if i > 0 && unicode.IsUpper(r) && unicode.IsLower(rs[i-1]) {
			b.WriteByte('_')
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteByte('_')
		}
	}
	var out []string
	for _, t := range strings.Split(b.String(), "_") {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

var secretWords = map[string]bool{
	"SECRET": true, "SECRETS": true, "PASSWORD": true, "PASSWD": true, "PASS": true, "PWD": true,
	"TOKEN": true, "TOKENS": true, "APIKEY": true, "CREDENTIAL": true, "CREDENTIALS": true,
	"SALT": true, "DSN": true, "PASSPHRASE": true, "AUTHTOKEN": true, "PRIVATEKEY": true,
	"SECRETKEY": true, "ACCESSKEY": true,
}

// keyPairs are two-token phrases that name a secret ("API KEY", "SIGNING KEY").
var keyPairs = map[string]bool{
	"API KEY": true, "ACCESS KEY": true, "PRIVATE KEY": true, "SIGNING KEY": true, "ENCRYPTION KEY": true,
	"MASTER KEY": true, "SECRET KEY": true, "AUTH KEY": true, "APP KEY": true, "LICENSE KEY": true,
	"ACCOUNT KEY": true, "CLIENT KEY": true, "SESSION KEY": true, "JWT KEY": true,
}

// nonSecretSuffix: a final token that turns a secret-ish key into metadata
// (PASSWORD_MIN_LENGTH, TOKEN_EXPIRY, SECRET_FILE, API_KEY_HEADER …).
var nonSecretSuffix = map[string]bool{
	"URL": true, "URI": true, "FILE": true, "PATH": true, "DIR": true, "LENGTH": true, "LEN": true,
	"MIN": true, "MAX": true, "TTL": true, "EXPIRY": true, "EXPIRES": true, "EXPIRATION": true,
	"LIFETIME": true, "TIMEOUT": true, "ENABLED": true, "ENABLE": true, "DISABLED": true,
	"HEADER": true, "NAME": true, "TYPE": true, "ALGORITHM": true, "ALG": true, "ENDPOINT": true,
	"HOST": true, "PORT": true, "USER": true, "USERNAME": true, "POLICY": true, "ROTATION": true,
	"FIELD": true, "PARAM": true, "PREFIX": true, "MODE": true, "VERSION": true, "METHOD": true,
	"COUNT": true, "SIZE": true, "LOCATION": true, "ID": true, "REGION": true, "PROVIDER": true,
	"ISSUER": true, "AUDIENCE": true, "SCOPE": true, "SCOPES": true, "RESET": true, "REQUIRED": true,
	"COMPLEXITY": true, "HASHER": true, "HASHERS": true, "BACKEND": true, "CLASS": true, "ATTEMPTS": true,
	"RETRIES": true, "DELAY": true, "INTERVAL": true, "EXPIRE": true, "AGE": true, "REFRESH": true,
}

// isSecretKey decides whether a key names a credential. Keys ending in KEY
// alone (CACHE_KEY, SORT_KEY) only count when the value itself looks random.
func isSecretKey(key, val string) bool {
	t := keyTokens(key)
	if len(t) == 0 {
		return false
	}
	if nonSecretSuffix[t[len(t)-1]] {
		return false
	}
	// PWD / OLDPWD are the shell's working directory; a path value is a
	// file reference (SECRET_FILE-style), not the secret itself.
	if len(t) == 1 && (t[0] == "PWD" || t[0] == "OLDPWD") {
		return false
	}
	if strings.HasPrefix(val, "/") || strings.HasPrefix(val, "~/") || strings.HasPrefix(val, "./") {
		return false
	}
	for i, tok := range t {
		if secretWords[tok] {
			return true
		}
		if i > 0 && keyPairs[t[i-1]+" "+tok] {
			return true
		}
	}
	last := t[len(t)-1]
	if last == "AUTH" && len(val) >= 12 {
		return true
	}
	if last == "KEY" && len(val) >= 20 && shannon(val) >= 3.5 {
		return true
	}
	return false
}

var reVarRef = regexp.MustCompile(`^(?:\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*\}\}|<%=.*%>|!(?:Ref|Sub|GetAtt)\b.*|\(\(.*\)\))$`)

// isStructural: the value opens a nested block (JSON [ { or YAML | >), not a secret.
func isStructural(v string) bool {
	switch strings.TrimSpace(v) {
	case "[", "{", "[]", "{}", "|", ">", "|-", ">-", "[{":
		return true
	}
	return false
}

// isVarRef: the value points elsewhere (${VAR}, $(cmd), {{tmpl}}) — not a secret.
func isVarRef(v string) bool { return reVarRef.MatchString(strings.TrimSpace(v)) }

var placeholderWords = []string{
	"your", "<", "xxx", "***", "replace", "example", "placeholder", "dummy", "todo", "fixme",
	"insert", "enter_", "enter-", "put_", "redacted", "...", "fake", "sample", "secret_here",
	"key_here", "here", "change_this", "set_me", "setme", "tbd", "n/a",
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	switch l {
	case "none", "null", "nil", "undefined", "false", "true", "0", "-":
		return true
	}
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	// one repeated character: "aaaaaaaa", "00000000"
	if len(l) >= 4 && strings.Count(l, l[:1]) == len(l) {
		return true
	}
	return false
}

var weakVals = map[string]bool{
	"password": true, "passw0rd": true, "p@ssw0rd": true, "p@ssword": true, "123456": true,
	"12345678": true, "123456789": true, "1234": true, "0000": true, "admin": true,
	"administrator": true, "changeme": true, "change_me": true, "change-me": true, "secret": true,
	"test": true, "testing": true, "root": true, "toor": true, "password1": true, "password123": true,
	"qwerty": true, "letmein": true, "default": true, "guest": true, "welcome": true, "master": true,
	"pass": true, "demo": true, "user": true, "postgres": true, "mysql": true, "redis": true,
	"admin123": true, "secret123": true, "abc123": true, "mysecret": true, "supersecret": true,
}

func isWeak(v string) bool { return weakVals[strings.ToLower(strings.TrimSpace(v))] }

var reBoolNum = regexp.MustCompile(`(?i)^(?:true|false|yes|no|on|off|\d{1,6})$`)

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "y":
		return true
	}
	return false
}
func falsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off", "n", "none", "disable", "disabled":
		return true
	}
	return false
}

// tokenPlaceholder reports documentation keys (AKIAIOSFODNN7EXAMPLE) and
// obviously synthetic tokens.
func tokenPlaceholder(tok string) bool {
	l := strings.ToLower(tok)
	if strings.Contains(l, "example") || strings.Contains(l, "xxxxxxxx") ||
		strings.Contains(l, "00000000") || strings.Contains(l, "your") {
		return true
	}
	return len(tok) >= 20 && shannon(tok) < 2.5
}

// ====================================================================
//  MASKING
// ====================================================================

var showSecrets bool

func mask(s string) string {
	if showSecrets {
		return s
	}
	r := []rune(s)
	n := len(r)
	switch {
	case n == 0:
		return "(empty)"
	case n <= 6:
		return strings.Repeat("•", n)
	case n < 12:
		return string(r[:2]) + "…" + fmt.Sprintf(" (%d)", n)
	}
	return string(r[:4]) + "…" + string(r[n-2:]) + fmt.Sprintf(" (%d)", n)
}

// maskURL keeps scheme/user/host visible and hides only the password.
func maskURL(u string) string {
	m := reURLCreds.FindStringSubmatch(u)
	if m == nil || showSecrets {
		return u
	}
	return m[1] + m[2] + ":" + strings.Repeat("•", 6) + "@" + m[4]
}

func fingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

// ====================================================================
//  PARSING
// ====================================================================

// fileKind selects the line grammar for a file.
type fileKind int

const (
	kindGeneric fileKind = iota
	kindEnv              // dotenv: export, quotes, multi-line values
	kindNetrc            // machine … login … password …
	kindPgpass           // host:port:db:user:password
	kindRaw              // source code etc.: every line, comments included, no key/value
)

type kvLine struct {
	line     int
	key, val string
	raw      string
	hasKV    bool
}

var (
	reExport = regexp.MustCompile(`^(?:export|set|setenv)\s+`)
	reDefine = regexp.MustCompile(`(?i)define\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]`)
	reKeyTok = regexp.MustCompile(`^[^\s=:]+$`)
)

// splitKV recognises KEY=VAL, KEY = VAL, KEY: VAL (YAML) and "KEY": "VAL" (JSON).
func splitKV(s string) (string, string, bool) {
	eq := strings.IndexByte(s, '=')
	colon := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
			colon = i
			break
		}
	}
	idx := eq
	if colon >= 0 && (eq < 0 || colon < eq) {
		idx = colon
	}
	if idx <= 0 {
		return "", "", false
	}
	k := strings.TrimSpace(s[:idx])
	k = strings.Trim(k, `"'`)
	if !reKeyTok.MatchString(k) && !(eq == idx && !strings.ContainsAny(k, " \t")) {
		return "", "", false
	}
	return k, strings.TrimSpace(s[idx+1:]), true
}

// cleanValue strips quotes, trailing JSON commas and inline comments.
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if q := v[0]; q == '"' || q == '\'' || q == '`' {
		for i := 1; i < len(v); i++ {
			if v[i] == '\\' && q == '"' {
				i++
				continue
			}
			if v[i] == q {
				return v[1:i]
			}
		}
		return strings.TrimRight(v[1:], ",")
	}
	if j := strings.Index(v, " #"); j >= 0 {
		v = v[:j]
	}
	v = strings.TrimSpace(v)
	return strings.TrimSpace(strings.TrimSuffix(v, ","))
}

func parseLines(data []byte, kind fileKind) []kvLine {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var out []kvLine
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		ln := strings.TrimSpace(raw)
		if kind == kindRaw {
			if ln != "" {
				out = append(out, kvLine{line: i + 1, raw: raw})
			}
			continue
		}
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") || strings.HasPrefix(ln, "//") {
			continue
		}
		e := kvLine{line: i + 1, raw: raw}
		switch kind {
		case kindNetrc:
			f := strings.Fields(ln)
			for j := 0; j+1 < len(f); j++ {
				if f[j] == "password" || f[j] == "passwd" {
					e.key, e.val, e.hasKV = "password", f[j+1], true
				}
			}
			out = append(out, e)
			continue
		case kindPgpass:
			if f := strings.Split(ln, ":"); len(f) == 5 {
				e.key, e.val, e.hasKV = "PGPASSWORD("+f[0]+"/"+f[3]+")", f[4], true
			}
			out = append(out, e)
			continue
		}
		if m := reDefine.FindStringSubmatch(ln); m != nil {
			e.key, e.val, e.hasKV = m[1], m[2], true
			out = append(out, e)
			continue
		}
		s := strings.TrimPrefix(ln, "- ")
		s = reExport.ReplaceAllString(s, "")
		if k, v, ok := splitKV(s); ok {
			// dotenv allows a quoted value to span lines (PEM keys)
			if kind == kindEnv && v != "" && (v[0] == '"' || v[0] == '\'') && strings.Count(v, v[:1]) == 1 {
				q := v[:1]
				for i+1 < len(lines) {
					i++
					v += "\n" + lines[i]
					e.raw += "\n" + lines[i]
					if strings.Contains(lines[i], q) {
						break
					}
				}
			}
			e.key, e.val, e.hasKV = k, cleanValue(v), true
		}
		out = append(out, e)
	}
	return out
}

// ====================================================================
//  FILE CLASSIFICATION
// ====================================================================

func isTemplate(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	for _, w := range []string{"example", "sample", "template", ".dist", "defaults", ".tmpl", ".tpl"} {
		if strings.Contains(b, w) {
			return true
		}
	}
	return false
}

func kindOf(path string) fileKind {
	b := strings.ToLower(filepath.Base(path))
	switch {
	case b == ".netrc" || b == "_netrc":
		return kindNetrc
	case b == ".pgpass":
		return kindPgpass
	case b == ".env" || strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env") ||
		b == ".envrc" || b == ".flaskenv":
		return kindEnv
	}
	return kindGeneric
}

// isTargetFile picks env / credential / config files during a tree walk.
func isTargetFile(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch b {
	case ".envrc", ".flaskenv", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc",
		".git-credentials", ".dockercfg", ".s3cfg", ".pgpass", ".my.cnf", "wp-config.php",
		"local_settings.py", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
		"config.env", ".boto":
		return true
	}
	if b == ".env" || strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env") {
		return true
	}
	if strings.HasSuffix(b, ".tfvars") || strings.HasSuffix(b, ".tfvars.json") {
		return true
	}
	if (dir == ".aws" && (b == "credentials" || b == "config")) || (dir == ".docker" && b == "config.json") {
		return true
	}
	if strings.HasPrefix(b, "application") && (strings.HasSuffix(b, ".properties") ||
		strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")) {
		return true
	}
	if strings.HasPrefix(b, "appsettings") && strings.HasSuffix(b, ".json") {
		return true
	}
	if strings.HasPrefix(b, "secrets.") || strings.HasPrefix(b, "credentials.") {
		// config formats only — secrets.py / credentials.go are source code
		switch strings.ToLower(filepath.Ext(b)) {
		case ".json", ".yml", ".yaml", ".env", ".ini", ".toml", ".conf", ".cfg", ".properties", ".txt":
			return true
		}
	}
	return false
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, ".cache": true, "dist": true, "build": true,
	"target": true, ".terraform": true, ".next": true, ".idea": true,
}

// ====================================================================
//  GIT CONTEXT
// ====================================================================

type gitState struct {
	inRepo, tracked, ignored, known bool
}

func gitRoot(path string) string {
	d, _ := filepath.Abs(filepath.Dir(path))
	for {
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			return ""
		}
		d = p
	}
}

var useGit = true

// gitStatusOf asks git whether path is tracked / ignored. Without a git
// binary it falls back to a simple .gitignore glob check (tracked unknown).
func gitStatusOf(path string) gitState {
	root := gitRoot(path)
	if root == "" || !useGit {
		return gitState{}
	}
	abs, _ := filepath.Abs(path)
	st := gitState{inRepo: true}
	if bin, err := exec.LookPath("git"); err == nil {
		dir, base := filepath.Dir(abs), filepath.Base(abs)
		st.tracked = exec.Command(bin, "-C", dir, "ls-files", "--error-unmatch", "--", base).Run() == nil
		st.ignored = exec.Command(bin, "-C", dir, "check-ignore", "-q", "--", base).Run() == nil
		st.known = true
		return st
	}
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return st
	}
	base := filepath.Base(abs)
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "/"))
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "!") {
			continue
		}
		if ok, _ := filepath.Match(strings.TrimSuffix(ln, "/"), base); ok {
			st.ignored = true
		}
	}
	return st
}

// ====================================================================
//  SCANNER
// ====================================================================

type valueLoc struct {
	file, key string
	line      int
}

type scanner struct {
	findings []Finding
	files    int
	values   map[string][]valueLoc // secret value → where it appears (reuse detection)
	warns    []string
	maxSize  int64
	excludes []string
	sup      *suppressor // .oenvscanignore + --baseline (nil = none)
}

func newScanner() *scanner {
	return &scanner{values: map[string][]valueLoc{}, maxSize: 4 << 20}
}

// scanContent runs every line-level rule over one file's content.
func (s *scanner) scanContent(name string, data []byte, kind fileKind, template bool) []Finding {
	var out []Finding
	seenKey := map[string]int{}
	pemBody := rePEMBody.Match(data)
	for _, e := range parseLines(data, kind) {
		if strings.Contains(e.raw, "oenvscan:ignore") {
			continue
		}
		sigHit := false
		for _, sg := range signatures {
			for _, m := range sg.re.FindAllString(e.raw, -1) {
				if sg.id == "ENV-OPENAI-KEY" && strings.HasPrefix(m, "sk-ant-") {
					continue
				}
				f := newFinding(sg.id, name, e.line, e.key, mask(m), "")
				f.secret, f.vfp = true, fingerprint(m)
				switch sg.id {
				case "ENV-URL-CREDS":
					pw := ""
					if mm := reURLCreds.FindStringSubmatch(m); mm != nil {
						pw = mm[3]
					}
					f.Evidence = maskURL(m)
					if isVarRef(pw) || isPlaceholder(pw) || strings.HasPrefix(pw, "$") || template && isWeak(pw) {
						f.Severity, f.Title, f.secret = SevInfo, f.Title+" (placeholder password)", false
					} else if isWeak(pw) {
						f.Detail = "password is a well-known default"
					}
				case "ENV-PRIVATE-KEY":
					f.Evidence = m
					if !pemBody {
						f.Severity, f.Title, f.secret = SevInfo, f.Title+" (header only, no key body)", false
					}
				case "ENV-JWT":
					f.Detail = jwtSummary(m)
				}
				if f.secret && tokenPlaceholder(m) {
					f.Severity, f.Title, f.secret = SevInfo, f.Title+" (documentation/example value)", false
				}
				if f.secret && template {
					f.Severity = maxSev(f.Severity, SevHigh)
					f.Detail = strings.TrimSpace(f.Detail + " found in a template file, which is normally committed")
				}
				out = append(out, f)
				sigHit = true
			}
		}
		if !e.hasKV {
			continue
		}
		key, val := e.key, e.val
		if kind == kindEnv {
			if prev, ok := seenKey[key]; ok {
				out = append(out, newFinding("ENV-DUP-KEY", name, e.line, key, "",
					fmt.Sprintf("also defined on line %d — this later value wins", prev)))
			}
			seenKey[key] = e.line
		}
		out = append(out, misconfig(name, e.line, key, val, template)...)
		if !isSecretKey(key, val) {
			if !sigHit && entropyOn {
				if f, ok := entropyFinding(name, e.line, key, val, template); ok {
					out = append(out, f)
				}
			}
			continue
		}
		if isVarRef(val) || isStructural(val) || reBoolNum.MatchString(val) && !strings.Contains(strings.ToUpper(key), "PASS") {
			continue
		}
		if len(val) >= 8 && !isPlaceholder(val) {
			s.values[val] = append(s.values[val], valueLoc{name, key, e.line})
		}
		if sigHit {
			continue
		}
		if f, ok := classifySecret(name, e.line, key, val, template); ok {
			if f.secret {
				f.vfp = fingerprint(val)
			}
			out = append(out, f)
		}
	}
	return collapseWordlist(name, out)
}

// collapseWordlist folds many weak defaults in one file (camera / router
// default-credential tables, test fixtures) into a single LOW finding.
func collapseWordlist(name string, fs []Finding) []Finding {
	n := 0
	for _, f := range fs {
		if f.RuleID == "ENV-WEAK" {
			n++
		}
	}
	if n < 5 {
		return fs
	}
	out := fs[:0:0]
	first := 0
	for _, f := range fs {
		switch f.RuleID {
		case "ENV-WEAK", "ENV-SHORT", "ENV-LOW-ENTROPY", "ENV-HARDCODED", "ENV-EMPTY", "ENV-PLACEHOLDER":
			if first == 0 || f.Line < first {
				first = f.Line
			}
			continue
		}
		if f.RuleID == "ENV-WEAK" {
			if first == 0 {
				first = f.Line
			}
			continue
		}
		out = append(out, f)
	}
	return append(out, newFinding("ENV-WEAK-LIST", name, first, "", fmt.Sprintf("%d weak values", n),
		"many well-known defaults in one file — reads like a wordlist, not live config"))
}

// classifySecret grades the value of a secret-named key.
func classifySecret(name string, line int, key, val string, template bool) (Finding, bool) {
	ent := shannon(val)
	n := utf8.RuneCountInString(val)
	stat := fmt.Sprintf("len=%d entropy=%.2f", n, ent)
	switch {
	case val == "":
		if template {
			return Finding{}, false
		}
		return newFinding("ENV-EMPTY", name, line, key, "", "secret key with a blank value"), true
	case isWeak(val):
		if template {
			return newFinding("ENV-PLACEHOLDER", name, line, key, mask(val), "default value in a template"), true
		}
		f := newFinding("ENV-WEAK", name, line, key, mask(val), "well-known default / dictionary value")
		f.secret = true
		return f, true
	case isPlaceholder(val):
		if template {
			return Finding{}, false
		}
		return newFinding("ENV-PLACEHOLDER", name, line, key, mask(val), "placeholder left in a live config"), true
	}
	if template {
		if n >= 12 && ent >= 3.0 {
			f := newFinding("ENV-EXAMPLE-SECRET", name, line, key, mask(val), stat)
			f.secret = true
			return f, true
		}
		return Finding{}, false
	}
	var f Finding
	switch {
	case n < 8:
		f = newFinding("ENV-SHORT", name, line, key, mask(val), stat)
	case ent < 3.0:
		f = newFinding("ENV-LOW-ENTROPY", name, line, key, mask(val), stat)
	default:
		f = newFinding("ENV-HARDCODED", name, line, key, mask(val), stat)
	}
	if t := keyTokens(key); len(t) > 0 && strings.Contains(strings.Join(t, "_"), "AWS") &&
		regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`).MatchString(val) {
		f = newFinding("ENV-AWS-SECRET", name, line, key, mask(val), stat)
	}
	f.secret = true
	return f, true
}

// ---- generic high-entropy detection ----

var (
	entropyOn  = true
	entropyMin = 4.0 // bits/char for mixed-case base62/64 values
	reTokChars = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)
	reHexOnly  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// hashWords: keys naming a digest / revision / build id, whose random-looking
// values are public identifiers (GIT_COMMIT, IMAGE_SHA, LOCK_CHECKSUM …).
var hashWords = map[string]bool{
	"SHA": true, "SHA1": true, "SHA256": true, "SHA512": true, "MD5": true, "HASH": true, "COMMIT": true,
	"REV": true, "REVISION": true, "CHECKSUM": true, "DIGEST": true, "ETAG": true, "INTEGRITY": true,
	"BUILD": true, "FINGERPRINT": true, "VERSION": true, "IMAGE": true, "TAG": true, "REF": true,
	"SUM": true, "UUID": true, "GUID": true, "CID": true,
}

// entropyFinding flags random-looking values under keys that do not name a
// secret (BLOB=…, CONN=…) — credentials the key classifier cannot see.
func entropyFinding(name string, line int, key, val string, template bool) (Finding, bool) {
	v := strings.TrimSpace(val)
	if len(v) < 20 || len(v) > 512 || isVarRef(v) || isPlaceholder(v) || tokenPlaceholder(v) ||
		reUUID.MatchString(v) || !reTokChars.MatchString(v) || strings.HasPrefix(v, "/") ||
		strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") || strings.HasPrefix(v, "~/") {
		return Finding{}, false // paths are file references, not values
	}
	t := keyTokens(key)
	if len(t) > 0 && nonSecretSuffix[t[len(t)-1]] {
		return Finding{}, false
	}
	for _, tok := range t {
		if hashWords[tok] {
			return Finding{}, false
		}
	}
	ent := shannon(v)
	stat := fmt.Sprintf("len=%d entropy=%.2f", len(v), ent)
	var f Finding
	if reHexOnly.MatchString(v) {
		if len(v) < 32 || ent < 3.5 {
			return Finding{}, false
		}
		f = newFinding("ENV-ENTROPY", name, line, key, mask(v), "hex "+stat)
		f.Severity = SevLow
	} else {
		var up, lo, dg int
		for _, r := range v {
			switch {
			case r >= 'A' && r <= 'Z':
				up++
			case r >= 'a' && r <= 'z':
				lo++
			case r >= '0' && r <= '9':
				dg++
			}
		}
		if up < 2 || lo < 2 || dg < 2 || ent < entropyMin {
			return Finding{}, false
		}
		f = newFinding("ENV-ENTROPY", name, line, key, mask(v), stat)
	}
	if template {
		f.Detail += " — in a template file"
	}
	f.secret, f.vfp = true, fingerprint(v)
	return f, true
}

var (
	reDebugKey   = regexp.MustCompile(`^(?:[A-Z0-9]+_)?DEBUG(?:_MODE)?$`)
	reTLSVerify  = regexp.MustCompile(`(?:SSL|TLS|CERT|HTTPS)[A-Z_]*(?:VERIFY|CHECK|VALIDAT)|VERIFY_(?:SSL|TLS|CERTS?|HTTPS)`)
	reTLSSkip    = regexp.MustCompile(`INSECURE|SKIP_(?:TLS_)?VERIFY|NO_VERIFY|SSL_NO_VERIFY|SKIP_SSL|DISABLE_SSL|DISABLE_TLS`)
	reDBSSLOff   = regexp.MustCompile(`(?i)sslmode=disable|[?&]ssl=false|usessl=false|tls=false`)
	reCookieFlag = regexp.MustCompile(`COOKIE_?(?:SECURE|HTTPONLY|HTTP_ONLY)|(?:SECURE|HTTPONLY)_COOKIE`)
)

// misconfig checks insecure settings that are not secrets themselves.
func misconfig(name string, line int, key, val string, template bool) []Finding {
	var out []Finding
	uk := strings.Join(keyTokens(key), "_")
	add := func(id, detail string) {
		f := newFinding(id, name, line, key, val, detail)
		if template {
			f.Severity, f.Detail = SevLow, strings.TrimSpace(detail+" (template default)")
		}
		out = append(out, f)
	}
	switch {
	case uk == "NODE_TLS_REJECT_UNAUTHORIZED" && falsy(val):
		add("ENV-TLS-OFF", "Node.js accepts any certificate for every HTTPS request")
	case uk == "PYTHONHTTPSVERIFY" && falsy(val):
		add("ENV-TLS-OFF", "Python stdlib HTTPS verification disabled process-wide")
	case reTLSVerify.MatchString(uk) && falsy(val):
		add("ENV-TLS-OFF", "certificate verification switched off — MITM risk")
	case reTLSSkip.MatchString(uk) && truthy(val):
		add("ENV-TLS-OFF", "insecure TLS mode enabled — MITM risk")
	}
	if reDebugKey.MatchString(uk) && truthy(val) && !template {
		add("ENV-DEBUG", "debug output / consoles exposed if this reaches production")
	}
	if (strings.Contains(uk, "CORS") || strings.Contains(uk, "ORIGIN")) && strings.Contains(val, "*") &&
		!strings.Contains(val, ".") {
		add("ENV-CORS", "any origin may make credentialed cross-site requests")
	}
	if (strings.HasSuffix(uk, "ALLOWED_HOSTS") || strings.HasSuffix(uk, "TRUSTED_HOSTS")) && strings.TrimSpace(val) == "*" {
		add("ENV-HOSTS", "Host header is not validated")
	}
	if reCookieFlag.MatchString(uk) && falsy(val) {
		add("ENV-COOKIE", "session cookie sent without the protective flag")
	}
	if strings.Contains(val, "://") && reDBSSLOff.MatchString(val) {
		f := newFinding("ENV-DB-SSL-OFF", name, line, key, maskURL(val), "connection string disables TLS")
		out = append(out, f)
	}
	return out
}

// jwtSummary decodes the JWT header/payload for the detail column.
func jwtSummary(tok string) string {
	parts := strings.Split(tok, ".")
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	h, p := dec(parts[0]), dec(parts[1])
	var bits []string
	if h != nil {
		if alg, ok := h["alg"].(string); ok {
			bits = append(bits, "alg="+alg)
			if strings.EqualFold(alg, "none") {
				bits = append(bits, "UNSIGNED")
			}
		}
	}
	if p != nil {
		if exp, ok := p["exp"].(float64); ok {
			t := time.Unix(int64(exp), 0).UTC()
			state := "valid until "
			if t.Before(time.Now()) {
				state = "expired "
			}
			bits = append(bits, state+t.Format("2006-01-02"))
		} else {
			bits = append(bits, "no exp (never expires)")
		}
	}
	return strings.Join(bits, ", ")
}

// fileContext adds git / permission findings for a file that held secrets.
func (s *scanner) fileContext(path string, fs []Finding, template bool) []Finding {
	nsec := 0
	for _, f := range fs {
		if f.secret && sevRank[f.Severity] >= sevRank[SevMedium] {
			nsec++
		}
	}
	if nsec == 0 {
		return nil
	}
	var out []Finding
	if fi, err := os.Stat(path); err == nil && !template {
		mode := fi.Mode().Perm()
		switch {
		case mode&0o004 != 0:
			out = append(out, newFinding("ENV-PERM-WORLD", path, 0, "", fmt.Sprintf("mode %04o", mode),
				fmt.Sprintf("%d secret(s) readable by every local user", nsec)))
		case mode&0o040 != 0:
			out = append(out, newFinding("ENV-PERM-GROUP", path, 0, "", fmt.Sprintf("mode %04o", mode),
				fmt.Sprintf("%d secret(s) readable by the file's group", nsec)))
		}
	}
	gs := gitStatusOf(path)
	switch {
	case gs.tracked:
		out = append(out, newFinding("ENV-GIT-TRACKED", path, 0, "", "git ls-files",
			fmt.Sprintf("%d secret(s) in a committed file — history keeps them even after deletion", nsec)))
	case gs.inRepo && !gs.ignored && !template:
		out = append(out, newFinding("ENV-GIT-UNIGNORED", path, 0, "", "git check-ignore",
			fmt.Sprintf("%d secret(s); `git add .` would commit them", nsec)))
	}
	return out
}

func (s *scanner) excluded(path string) bool {
	for _, pat := range s.excludes {
		if ok, _ := filepath.Match(pat, filepath.Base(path)); ok {
			return true
		}
		if strings.Contains(path, pat) {
			return true
		}
	}
	return false
}

// ScanFile scans one file (any name — explicit paths are never filtered).
func (s *scanner) ScanFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return s.ScanTree(path)
	}
	if fi.Size() > s.maxSize {
		s.warns = append(s.warns, fmt.Sprintf("%s skipped (%d bytes > max)", path, fi.Size()))
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.IndexByte(data, 0) >= 0 {
		s.warns = append(s.warns, path+" skipped (binary)")
		return nil
	}
	s.files++
	tmpl := isTemplate(path)
	fs := s.scanContent(path, data, kindOf(path), tmpl)
	fs = append(fs, s.fileContext(path, fs, tmpl)...)
	s.findings = append(s.findings, fs...)
	s.drift(path)
	return nil
}

// ScanTree walks root for env / credential files.
func (s *scanner) ScanTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.warns = append(s.warns, err.Error())
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || s.excluded(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isTargetFile(path) || s.excluded(path) {
			return nil
		}
		if err := s.ScanFile(path); err != nil {
			s.warns = append(s.warns, err.Error())
		}
		return nil
	})
}

// ScanEnviron scans KEY=VALUE pairs from a process environment.
func (s *scanner) ScanEnviron(label string, env []string) {
	var buf bytes.Buffer
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.ContainsAny(v, "\n") {
			continue
		}
		buf.WriteString(k + "=" + strconv.Quote(v) + "\n")
	}
	s.files++
	fs := s.scanContent(label, buf.Bytes(), kindEnv, false)
	for i := range fs {
		fs[i].Line = 0 // line numbers of the synthetic buffer mean nothing
	}
	s.findings = append(s.findings, fs...)
}

// ScanProcs reads /proc/<pid>/environ for every process this user can read.
// Identical findings across processes are collapsed into one.
func (s *scanner) ScanProcs() (int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	n := 0
	seen := map[string]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || len(data) == 0 {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		label := fmt.Sprintf("pid %d (%s)", pid, strings.TrimSpace(string(comm)))
		n++
		var env []string
		for _, kv := range bytes.Split(data, []byte{0}) {
			if len(kv) > 0 {
				env = append(env, string(kv))
			}
		}
		sub := newScanner()
		sub.ScanEnviron(label, env)
		for _, f := range sub.findings {
			k := f.RuleID + "|" + f.Key + "|" + f.Evidence
			if i, ok := seen[k]; ok {
				s.findings[i].Detail = bumpProcCount(s.findings[i].Detail)
				continue
			}
			seen[k] = len(s.findings)
			f.Line = 0
			s.findings = append(s.findings, f)
		}
		for v, locs := range sub.values {
			s.values[v] = append(s.values[v], locs...)
		}
	}
	s.files += n
	return n, nil
}

var reProcCount = regexp.MustCompile(`\(\+(\d+) more processes?\)$`)

func bumpProcCount(d string) string {
	if m := reProcCount.FindStringSubmatch(d); m != nil {
		n, _ := strconv.Atoi(m[1])
		return strings.TrimSpace(reProcCount.ReplaceAllString(d, "")) + fmt.Sprintf(" (+%d more processes)", n+1)
	}
	return strings.TrimSpace(d + " (+1 more process)")
}

// drift compares a .env with its sibling template (.env.example etc.).
func (s *scanner) drift(path string) {
	if kindOf(path) != kindEnv || isTemplate(path) {
		return
	}
	dir := filepath.Dir(path)
	for _, t := range templateNames {
		tp := filepath.Join(dir, t)
		if _, err := os.Stat(tp); err == nil {
			s.findings = append(s.findings, compareDrift(path, tp)...)
			return
		}
	}
}

func envKeys(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]int{}
	for _, e := range parseLines(data, kindEnv) {
		if e.hasKV {
			if _, ok := keys[e.key]; !ok {
				keys[e.key] = e.line
			}
		}
	}
	return keys, nil
}

func compareDrift(envPath, tmplPath string) []Finding {
	ek, err1 := envKeys(envPath)
	tk, err2 := envKeys(tmplPath)
	if err1 != nil || err2 != nil {
		return nil
	}
	var out []Finding
	for k, ln := range tk {
		if _, ok := ek[k]; !ok {
			out = append(out, newFinding("ENV-DRIFT-MISSING", envPath, 0, k, "",
				fmt.Sprintf("declared in %s:%d", filepath.Base(tmplPath), ln)))
		}
	}
	for k, ln := range ek {
		if _, ok := tk[k]; !ok {
			out = append(out, newFinding("ENV-DRIFT-UNDOC", envPath, ln, k, "",
				"not in "+filepath.Base(tmplPath)))
		}
	}
	return out
}

// Finish adds cross-file findings (reuse), filters, sorts and grades.
func (s *scanner) Finish(target, minSev string) Report {
	vals := make([]string, 0, len(s.values))
	for v := range s.values {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	for _, v := range vals {
		locs := s.values[v]
		keys := map[string]bool{}
		for _, l := range locs {
			keys[l.key] = true
		}
		if len(keys) < 2 {
			continue
		}
		var where []string
		for _, l := range locs {
			w := l.key + "@" + filepath.Base(l.file)
			if l.line > 0 {
				w += ":" + strconv.Itoa(l.line)
			}
			where = append(where, w)
		}
		f := newFinding("ENV-REUSE", locs[0].file, locs[0].line, locs[0].key, mask(v),
			fmt.Sprintf("value #%s shared by %d keys: %s", fingerprint(v), len(keys), strings.Join(uniq(where), ", ")))
		s.findings = append(s.findings, f)
	}
	var fs []Finding
	suppressed := 0
	for _, f := range s.findings {
		f.Fingerprint = findingFP(f)
		if s.sup.match(f) {
			suppressed++
			continue
		}
		if sevRank[f.Severity] >= sevRank[minSev] {
			fs = append(fs, f)
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank[fs[i].Severity] != sevRank[fs[j].Severity] {
			return sevRank[fs[i].Severity] > sevRank[fs[j].Severity]
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
	if fs == nil {
		fs = []Finding{}
	}
	rep := Report{Tool: APPNAME, Version: VERSION, Target: target, Files: s.files, Suppressed: suppressed,
		Generated: time.Now().UTC().Format(time.RFC3339), Findings: fs, Counts: map[string]int{}}
	for _, sv := range sevOrder {
		rep.Counts[sv] = 0
	}
	for _, f := range fs {
		rep.Counts[f.Severity]++
	}
	rep.Score, rep.Grade = grade(rep.Counts)
	return rep
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// grade: start at 100, subtract per severity; any CRITICAL caps at D, any HIGH at C.
func grade(c map[string]int) (int, string) {
	score := 100 - c[SevCritical]*25 - c[SevHigh]*12 - c[SevMedium]*5 - c[SevLow]*1
	if score < 0 {
		score = 0
	}
	g := "F"
	switch {
	case score >= 97:
		g = "A+"
	case score >= 90:
		g = "A"
	case score >= 80:
		g = "B"
	case score >= 70:
		g = "C"
	case score >= 55:
		g = "D"
	}
	rank := map[string]int{"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
	if c[SevCritical] > 0 && rank[g] > rank["D"] {
		g = "D"
	} else if c[SevHigh] > 0 && rank[g] > rank["C"] {
		g = "C"
	}
	return score, g
}

func gradeColor(g string) string {
	switch g {
	case "A+", "A":
		return col(g, GRN+B)
	case "B":
		return col(g, CY+B)
	case "C":
		return col(g, YLW+B)
	case "D":
		return col(g, OR+B)
	}
	return col(g, R+B)
}

// ====================================================================
//  RENDERING / EXPORT
// ====================================================================

func location(f Finding) string {
	loc := f.File
	if f.Line > 0 {
		loc += ":" + strconv.Itoa(f.Line)
	}
	return loc
}

func printReport(rep Report, warns []string) {
	sectionHeader("Scan Report")
	kv("Target", rep.Target)
	kv("Files scanned", strconv.Itoa(rep.Files))
	var cs []string
	for _, sv := range sevOrder {
		cs = append(cs, sevColor(fmt.Sprintf("%s %d", sv, rep.Counts[sv])))
	}
	kv("Findings", strings.Join(cs, col("  ·  ", DIM)))
	kv("Posture", gradeColor(rep.Grade)+col(fmt.Sprintf("  (score %d/100)", rep.Score), DIM))
	if rep.Suppressed > 0 {
		kv("Suppressed", fmt.Sprintf("%d (ignore file / baseline)", rep.Suppressed))
	}
	fmt.Println()
	for _, w := range warns {
		warnMsg(w)
	}
	if len(rep.Findings) == 0 {
		okMsg("No secrets or misconfigurations detected.")
		return
	}
	var rows [][]string
	for _, f := range rep.Findings {
		rows = append(rows, []string{sevColor(f.Severity), f.RuleID, truncLeft(location(f), 34),
			trunc(f.Key, 26), trunc(f.Evidence, 30)})
	}
	table([]string{"SEV", "RULE", "LOCATION", "KEY", "EVIDENCE"}, rows)
	fmt.Println()
	// one remediation line per rule that fired
	sectionHeader("What to do")
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if seen[f.RuleID] || f.Severity == SevInfo {
			continue
		}
		seen[f.RuleID] = true
		fmt.Println("  " + sevColor(pad(f.Severity, 8)) + " " + col(f.Title, W+B))
		fmt.Println("           " + col("→ "+f.Fix, DIM))
	}
	notes := 0
	for _, f := range rep.Findings {
		if f.Detail != "" && sevRank[f.Severity] >= sevRank[SevHigh] {
			if notes == 0 {
				fmt.Println()
				sectionHeader("Details (HIGH and above)")
			}
			if notes++; notes > 25 {
				info("… more in the exported report")
				break
			}
			fmt.Println("  " + col("•", CY) + " " + col(location(f), W) + col("  "+f.Detail, DIM))
		}
	}
}

func exportTXT(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s v%s — %s\n", APPNAME, VERSION, TAGLINE)
	fmt.Fprintf(&b, "Target   : %s\nGenerated: %s\nFiles    : %d\nGrade    : %s (%d/100)\n", r.Target, r.Generated, r.Files, r.Grade, r.Score)
	if r.Suppressed > 0 {
		fmt.Fprintf(&b, "Suppressed: %d (ignore file / baseline)\n", r.Suppressed)
	}
	for _, sv := range sevOrder {
		fmt.Fprintf(&b, "  %-8s %d\n", sv, r.Counts[sv])
	}
	b.WriteString(strings.Repeat("-", 66) + "\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s  %s\n  at %s", f.Severity, f.RuleID, f.Title, location(f))
		if f.Key != "" {
			fmt.Fprintf(&b, "  key=%s", f.Key)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "  evidence=%s", f.Evidence)
		}
		b.WriteString("\n")
		if f.Detail != "" {
			fmt.Fprintf(&b, "  detail: %s\n", f.Detail)
		}
		if f.Fix != "" {
			fmt.Fprintf(&b, "  fix   : %s\n", f.Fix)
		}
	}
	return b.String()
}

func mdEsc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }

func exportMD(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s report\n\n", APPNAME)
	fmt.Fprintf(&b, "- **Target:** `%s`\n- **Generated:** %s\n- **Files scanned:** %d\n- **Grade:** %s (%d/100)\n\n", r.Target, r.Generated, r.Files, r.Grade, r.Score)
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sv := range sevOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", sv, r.Counts[sv])
	}
	b.WriteString("\n| Sev | Rule | Location | Key | Evidence | Detail |\n|---|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | `%s` | %s |\n", f.Severity, f.RuleID, mdEsc(location(f)),
			mdEsc(f.Key), mdEsc(f.Evidence), mdEsc(f.Detail))
	}
	return b.String()
}

func exportJSON(r Report) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b) + "\n"
}

func exportCSV(r Report) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"severity", "rule_id", "title", "file", "line", "key", "evidence", "detail", "fix"})
	for _, f := range r.Findings {
		w.Write([]string{f.Severity, f.RuleID, f.Title, f.File, strconv.Itoa(f.Line), f.Key, f.Evidence, f.Detail, f.Fix})
	}
	w.Flush()
	return b.String()
}

func exportSARIF(r Report) string {
	level := func(s string) string {
		switch s {
		case SevCritical, SevHigh:
			return "error"
		case SevMedium:
			return "warning"
		}
		return "note"
	}
	used := map[string]bool{}
	var results []map[string]any
	for _, f := range r.Findings {
		used[f.RuleID] = true
		loc := map[string]any{"artifactLocation": map[string]any{"uri": filepath.ToSlash(f.File)}}
		if f.Line > 0 {
			loc["region"] = map[string]any{"startLine": f.Line}
		}
		msg := f.Title
		if f.Key != "" {
			msg += " (" + f.Key + ")"
		}
		if f.Detail != "" {
			msg += " — " + f.Detail
		}
		results = append(results, map[string]any{
			"ruleId": f.RuleID, "level": level(f.Severity),
			"message":   map[string]any{"text": msg},
			"locations": []any{map[string]any{"physicalLocation": loc}},
			"partialFingerprints": map[string]any{
				"oenvscan/v1": f.Fingerprint},
		})
	}
	var rules []map[string]any
	for _, ri := range ruleCatalog {
		if used[ri.ID] {
			rules = append(rules, map[string]any{"id": ri.ID, "name": ri.Title,
				"shortDescription":     map[string]any{"text": ri.Title},
				"help":                 map[string]any{"text": ri.Fix},
				"defaultConfiguration": map[string]any{"level": level(ri.Sev)}})
		}
	}
	if results == nil {
		results = []map[string]any{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": APPNAME, "version": VERSION,
				"informationUri": "https://" + WEBSITE, "rules": rules}},
			"results": results}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b) + "\n"
}

func render(r Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "txt", "text":
		return exportTXT(r), nil
	case "md", "markdown":
		return exportMD(r), nil
	case "json":
		return exportJSON(r), nil
	case "csv":
		return exportCSV(r), nil
	case "sarif":
		return exportSARIF(r), nil
	}
	return "", fmt.Errorf("unknown format %q (txt|md|json|csv|sarif)", format)
}

func writeOut(content, path string) error {
	if path == "" || path == "-" {
		fmt.Print(content)
		return nil
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// ====================================================================
//  TOKEN / ENTROPY CHECK
// ====================================================================

type tokenVerdict struct {
	length   int
	entropy  float64
	charset  int
	bits     float64
	matches  []string
	weak     bool
	verdict  string
	severity string
}

func assessToken(v string) tokenVerdict {
	t := tokenVerdict{length: utf8.RuneCountInString(v), entropy: shannon(v)}
	var lower, upper, digit, sym bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			sym = true
		}
	}
	for _, c := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {sym, 33}} {
		if c.on {
			t.charset += c.n
		}
	}
	if t.charset > 0 {
		// the smaller of the brute-force bound and the observed entropy
		t.bits = math.Min(float64(t.length)*math.Log2(float64(t.charset)), t.entropy*float64(t.length))
	}
	for _, sg := range signatures {
		if sg.re.MatchString(v) && !(sg.id == "ENV-OPENAI-KEY" && strings.HasPrefix(v, "sk-ant-")) {
			t.matches = append(t.matches, ruleByID[sg.id].Title)
		}
	}
	t.weak = isWeak(v)
	switch {
	case t.weak:
		t.verdict, t.severity = "Well-known default — trivially guessable", SevHigh
	case len(t.matches) > 0:
		t.verdict, t.severity = "Matches a provider token format: "+strings.Join(t.matches, ", "), SevHigh
	case t.bits >= 128:
		t.verdict, t.severity = "Strong random secret (≥128 bits)", SevInfo
	case t.bits >= 80:
		t.verdict, t.severity = "Reasonable strength (80–128 bits)", SevLow
	case t.bits >= 50:
		t.verdict, t.severity = "Weak for a signing/API key (<80 bits)", SevMedium
	default:
		t.verdict, t.severity = "Guessable (<50 bits)", SevHigh
	}
	return t
}

func entropyBar(bits float64) string {
	n := int(math.Min(bits/128*30, 30))
	c := R
	switch {
	case bits >= 128:
		c = GRN
	case bits >= 80:
		c = CY
	case bits >= 50:
		c = YLW
	}
	return col(strings.Repeat("█", n), c) + col(strings.Repeat("░", 30-n), DIM)
}

// ====================================================================
//  BASELINE / IGNORE
// ====================================================================

// relPath makes a path relative to the working directory when it lies below
// it, so fingerprints match between `OEnvScan .` and `OEnvScan $PWD`.
func relPath(p string) string {
	if !filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
			return r
		}
	}
	return p
}

var rePidLabel = regexp.MustCompile(`^pid \d+ `)

// findingFP: rule + path + key + value hash. No line number, so edits above
// a finding do not invalidate a baseline; pids are dropped for /proc scans.
func findingFP(f Finding) string {
	file := filepath.ToSlash(rePidLabel.ReplaceAllString(relPath(f.File), ""))
	v := f.vfp
	if v == "" {
		v = f.Evidence
	}
	return fingerprint(f.RuleID + "\x00" + file + "\x00" + f.Key + "\x00" + v)
}

type ignoreRule struct {
	rule, glob string // either may be empty
}

// suppressor hides accepted findings. Sources: .oenvscanignore files
// (rule ids, path globs, RULE:glob, fp:<fingerprint>) and a --baseline file.
type suppressor struct {
	rules    []ignoreRule
	fps      map[string]bool
	sources  []string
	baseline int
}

var reRuleID = regexp.MustCompile(`^ENV-[A-Z0-9-]+$`)

func (sp *suppressor) loadIgnore(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sp.fps == nil {
		sp.fps = map[string]bool{}
	}
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if i := strings.Index(ln, " #"); i >= 0 {
			ln = strings.TrimSpace(ln[:i])
		}
		switch {
		case ln == "" || strings.HasPrefix(ln, "#"):
		case strings.HasPrefix(ln, "fp:"):
			sp.fps[strings.TrimSpace(ln[3:])] = true
		case reRuleID.MatchString(ln):
			sp.rules = append(sp.rules, ignoreRule{rule: ln})
		default:
			r, g, ok := strings.Cut(ln, ":")
			if ok && reRuleID.MatchString(r) {
				sp.rules = append(sp.rules, ignoreRule{rule: r, glob: g})
			} else {
				sp.rules = append(sp.rules, ignoreRule{glob: ln})
			}
		}
	}
	sp.sources = append(sp.sources, path)
	return nil
}

// loadBaseline accepts a baseline written by --write-baseline or any
// OEnvScan JSON report (its findings[].fingerprint).
func (sp *suppressor) loadBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Fingerprints []struct {
			FP string `json:"fp"`
		} `json:"fingerprints"`
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: not an OEnvScan baseline / JSON report: %v", path, err)
	}
	if sp.fps == nil {
		sp.fps = map[string]bool{}
	}
	for _, f := range doc.Fingerprints {
		sp.fps[f.FP] = true
		sp.baseline++
	}
	for _, f := range doc.Findings {
		if f.Fingerprint != "" {
			sp.fps[f.Fingerprint] = true
			sp.baseline++
		}
	}
	sp.sources = append(sp.sources, path)
	return nil
}

func globMatch(g, p string) bool {
	g = filepath.ToSlash(strings.TrimPrefix(g, "./"))
	if ok, _ := filepath.Match(g, p); ok {
		return true
	}
	if ok, _ := filepath.Match(g, path.Base(p)); ok {
		return true
	}
	// a directory pattern ("tests/fixtures/") covers everything below it
	d := strings.TrimSuffix(g, "/") + "/"
	return strings.HasPrefix(p, d) || strings.Contains(p, "/"+d)
}

func (sp *suppressor) match(f Finding) bool {
	if sp == nil {
		return false
	}
	if sp.fps[f.Fingerprint] {
		return true
	}
	p := filepath.ToSlash(relPath(f.File))
	for _, r := range sp.rules {
		if r.rule != "" && r.rule != f.RuleID {
			continue
		}
		if r.glob == "" || globMatch(r.glob, p) {
			return true
		}
	}
	return false
}

// loadSuppressor collects .oenvscanignore from the working directory, every
// scanned directory and its git root, plus an explicit ignore file / baseline.
func loadSuppressor(roots []string, ignoreFile, baseline string) (*suppressor, error) {
	sp := &suppressor{fps: map[string]bool{}}
	seen := map[string]bool{}
	try := func(dir string) {
		p, _ := filepath.Abs(filepath.Join(dir, ".oenvscanignore"))
		if seen[p] {
			return
		}
		seen[p] = true
		if _, err := os.Stat(p); err == nil {
			_ = sp.loadIgnore(p)
		}
	}
	try(".")
	for _, r := range roots {
		dir := r
		if fi, err := os.Stat(r); err == nil && !fi.IsDir() {
			dir = filepath.Dir(r)
		}
		try(dir)
		if g := gitRoot(filepath.Join(dir, "_")); g != "" {
			try(g)
		}
	}
	if ignoreFile != "" {
		if err := sp.loadIgnore(ignoreFile); err != nil {
			return nil, err
		}
	}
	if baseline != "" {
		if err := sp.loadBaseline(baseline); err != nil {
			return nil, err
		}
	}
	if len(sp.sources) == 0 {
		return nil, nil
	}
	return sp, nil
}

func writeBaseline(r Report, out string) error {
	type ent struct {
		FP   string `json:"fp"`
		Rule string `json:"rule"`
		File string `json:"file"`
		Key  string `json:"key,omitempty"`
	}
	doc := struct {
		Tool         string `json:"tool"`
		Version      string `json:"version"`
		Created      string `json:"created"`
		Fingerprints []ent  `json:"fingerprints"`
	}{APPNAME, VERSION, time.Now().UTC().Format(time.RFC3339), []ent{}}
	for _, f := range r.Findings {
		doc.Fingerprints = append(doc.Fingerprints, ent{f.Fingerprint, f.RuleID, relPath(f.File), f.Key})
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return os.WriteFile(out, append(b, '\n'), 0o600)
}

// ====================================================================
//  GIT HISTORY
// ====================================================================

var historyMax = 1000

// sigIDs: provider-format rules, precise enough to run on any file in history
// (source code included); key/value rules only run on env/config files.
var sigIDs = func() map[string]bool {
	m := map[string]bool{}
	for _, sg := range signatures {
		m[sg.id] = true
	}
	return m
}()

var reHunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// histChunk is the lines one commit added to one file.
type histChunk struct {
	commit, author, date, path string
	lines                      []string
	nums                       []int
}

type histHit struct {
	idx  int // index into s.findings
	path string
}

var reTestPath = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|spec|fixtures?|testdata|__tests__|mocks?)(?:/|$)|_test\.|\.test\.|\.spec\.`)

// isTestPath: fixtures in test trees are usually fake; they keep their
// native severity instead of being escalated like a real leak.
func isTestPath(p string) bool { return reTestPath.MatchString(filepath.ToSlash(p)) }

func inSkipDir(p string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if skipDirs[part] {
			return true
		}
	}
	return false
}

// ScanHistory reads `git log -p` of the repository holding root and reports
// every secret any commit added — including ones later deleted, which every
// clone still carries. Returns the number of commits read.
func (s *scanner) ScanHistory(root string) (int, error) {
	bin, err := exec.LookPath("git")
	if err != nil {
		return 0, errors.New("git not found in PATH")
	}
	probe := root
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		probe = filepath.Join(root, "_")
	}
	repo := gitRoot(probe)
	if repo == "" {
		return 0, fmt.Errorf("%s is not inside a git repository", root)
	}
	args := []string{"-C", repo, "-c", "core.quotepath=off", "log", "--all", "-p", "-U0", "--no-color",
		"--no-ext-diff", "--no-renames", "--diff-filter=AM", "--format=%x01C %H%x09%an%x09%ad", "--date=short"}
	if historyMax > 0 {
		args = append(args, fmt.Sprintf("--max-count=%d", historyMax))
	}
	cmd := exec.Command(bin, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	disp := relPath(repo)
	hits := map[string]histHit{}
	var cur histChunk
	commits, next, inHeader := 0, 0, false
	flush := func() {
		if cur.path != "" && len(cur.lines) > 0 {
			s.historyChunk(disp, cur, hits)
		}
		cur.lines, cur.nums = nil, nil
	}
	rd := bufio.NewReaderSize(pipe, 1<<16)
	for {
		l, rerr := rd.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		switch {
		case strings.HasPrefix(l, "\x01C "):
			flush()
			p := strings.SplitN(l[3:], "\t", 3)
			for len(p) < 3 {
				p = append(p, "")
			}
			cur = histChunk{commit: p[0], author: p[1], date: p[2]}
			commits++
		case strings.HasPrefix(l, "diff --git "):
			flush()
			cur.path, inHeader = "", true
		case inHeader && strings.HasPrefix(l, "+++ "):
			cur.path = ""
			if p := l[4:]; p != "/dev/null" {
				// git appends a tab to paths containing spaces
				cur.path = strings.TrimPrefix(strings.TrimSuffix(p, "\t"), "b/")
			}
		case strings.HasPrefix(l, "@@"):
			inHeader = false
			if m := reHunk.FindStringSubmatch(l); m != nil {
				next, _ = strconv.Atoi(m[1])
			}
		case !inHeader && strings.HasPrefix(l, "+"):
			if cur.path != "" && len(l) <= 8192 {
				cur.lines = append(cur.lines, l[1:])
				cur.nums = append(cur.nums, next)
			}
			next++
		}
		if rerr != nil {
			break
		}
	}
	flush()
	if err := cmd.Wait(); err != nil && commits == 0 {
		return 0, fmt.Errorf("git log: %v (empty repository?)", err)
	}
	// is each secret still in HEAD, or only in history?
	head := map[string]map[string]bool{}
	for _, h := range hits {
		vf, ok := head[h.path]
		if !ok {
			vf = map[string]bool{}
			if data, err := exec.Command(bin, "-C", repo, "show", "HEAD:"+h.path).Output(); err == nil {
				kind := kindRaw
				if isTargetFile(h.path) {
					kind = kindOf(h.path)
				}
				for _, f := range newScanner().scanContent(h.path, data, kind, isTemplate(h.path)) {
					vf[f.vfp] = true
				}
			} else {
				vf = nil // file no longer exists at HEAD
			}
			head[h.path] = vf
		}
		f := &s.findings[h.idx]
		if vf[f.vfp] {
			f.Detail += " — still present in HEAD"
		} else if vf == nil {
			f.Detail += " — file deleted since, but every clone still has it"
		} else {
			f.Detail += " — removed from HEAD, but every clone still has it"
		}
	}
	s.files++
	return commits, nil
}

// historyChunk scans what one commit added to one file. git log runs newest
// first, so a later sighting of the same secret moves it to an older commit:
// the finding names the commit that introduced it.
func (s *scanner) historyChunk(repo string, c histChunk, hits map[string]histHit) {
	if s.excluded(c.path) || inSkipDir(c.path) {
		return
	}
	target := isTargetFile(c.path)
	kind := kindRaw
	if target {
		kind = kindOf(c.path)
	}
	for _, f := range newScanner().scanContent(c.path, []byte(strings.Join(c.lines, "\n")), kind, isTemplate(c.path)) {
		if !f.secret || f.vfp == "" || !target && !sigIDs[f.RuleID] {
			continue
		}
		short := c.commit
		if len(short) > 10 {
			short = short[:10]
		}
		line := 0
		if f.Line >= 1 && f.Line <= len(c.nums) {
			line = c.nums[f.Line-1]
		}
		sev, what := f.Severity, ruleByID[f.RuleID].Title
		if isTestPath(c.path) {
			what += " (test fixture)"
		} else if sevRank[sev] >= sevRank[SevMedium] {
			sev = maxSev(sev, SevHigh)
		}
		h := newFinding("ENV-GIT-HISTORY", filepath.Join(repo, c.path), line, f.Key, f.Evidence,
			fmt.Sprintf("%s added in commit %s (%s, %s)", what, short, c.author, c.date))
		h.Severity, h.secret, h.vfp = sev, true, f.vfp
		k := f.vfp + "|" + c.path
		if old, ok := hits[k]; ok {
			s.findings[old.idx] = h
			continue
		}
		hits[k] = histHit{len(s.findings), c.path}
		s.findings = append(s.findings, h)
	}
}

// ====================================================================
//  FIX MODE
// ====================================================================

type fixAction struct {
	desc   string
	manual bool         // advice only — needs a human (rotation, history rewrite)
	do     func() error // nil when manual
}

var templateNames = []string{".env.example", ".env.sample", ".env.template", ".env.dist", "env.example"}

// planFixes turns a report into safe local remediations: tighten perms,
// git-ignore secret files, and write a sanitised .env.example where none
// exists. Secrets themselves are never edited — rotation stays manual.
func planFixes(r Report) []fixAction {
	var out []fixAction
	done := map[string]bool{}
	once := func(k string) bool {
		if done[k] {
			return false
		}
		done[k] = true
		return true
	}
	for _, f := range r.Findings {
		file := f.File
		switch f.RuleID {
		case "ENV-PERM-WORLD", "ENV-PERM-GROUP":
			if once("chmod|" + file) {
				out = append(out, fixAction{desc: "chmod 600 " + file, do: func() error { return os.Chmod(file, 0o600) }})
			}
		case "ENV-GIT-UNIGNORED", "ENV-GIT-TRACKED":
			root := gitRoot(file)
			abs, _ := filepath.Abs(file)
			rel, err := filepath.Rel(root, abs)
			if root == "" || err != nil {
				continue
			}
			entry := "/" + filepath.ToSlash(rel)
			gi := filepath.Join(root, ".gitignore")
			if once("ignore|"+entry) && !fileHasLine(gi, entry) {
				out = append(out, fixAction{desc: "add " + entry + " to " + relPath(gi),
					do: func() error { return appendLine(gi, entry) }})
			}
			if f.RuleID == "ENV-GIT-TRACKED" && once("untrack|"+file) {
				out = append(out, fixAction{manual: true, desc: fmt.Sprintf(
					"git -C %s rm --cached -- %s, then ROTATE its secrets (history keeps them)", relPath(root), filepath.ToSlash(rel))})
			}
		case "ENV-GIT-HISTORY":
			if once("history|" + f.Fingerprint) {
				out = append(out, fixAction{manual: true, desc: fmt.Sprintf("rotate %s (%s), then purge history: %s",
					orDash(f.Key), location(f), "git filter-repo --replace-text / BFG")})
			}
		}
		if kindOf(file) == kindEnv && !isTemplate(file) && f.secret && f.RuleID != "ENV-GIT-HISTORY" && once("tmpl|"+filepath.Dir(file)) {
			if _, err := os.Stat(file); err != nil {
				continue
			}
			dir, has := filepath.Dir(file), false
			for _, t := range templateNames {
				if _, err := os.Stat(filepath.Join(dir, t)); err == nil {
					has = true
				}
			}
			if !has {
				dst := filepath.Join(dir, ".env.example")
				out = append(out, fixAction{desc: "write sanitised " + relPath(dst) + " (keys kept, secrets blanked)",
					do: func() error {
						data, err := os.ReadFile(file)
						if err != nil {
							return err
						}
						return os.WriteFile(dst, []byte(sanitizeEnv(filepath.Base(file), data)), 0o644)
					}})
			}
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "value"
	}
	return s
}

func fileHasLine(p, line string) bool {
	data, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

func appendLine(p, line string) error {
	data, _ := os.ReadFile(p)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(data) > 0 && data[len(data)-1] != '\n' {
		line = "\n" + line
	}
	_, err = f.WriteString(line + "\n")
	return err
}

// templateValue keeps harmless settings (PORT=8080) and blanks anything that
// looks like a credential; URL passwords become CHANGE_ME.
func templateValue(key, val string) string {
	if val == "" || isVarRef(val) || isPlaceholder(val) {
		return val
	}
	if m := reURLCreds.FindStringSubmatch(val); m != nil {
		return m[1] + m[2] + ":CHANGE_ME@" + m[4]
	}
	for _, sg := range signatures {
		if sg.re.MatchString(val) {
			return ""
		}
	}
	if isSecretKey(key, val) {
		return ""
	}
	if _, ok := entropyFinding("", 0, key, val, false); ok {
		return ""
	}
	if strings.ContainsAny(val, " #\"'\\") {
		return strconv.Quote(val)
	}
	return val
}

func sanitizeEnv(src string, data []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	byLine := map[int]kvLine{}
	for _, e := range parseLines(data, kindEnv) {
		byLine[e.line] = e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Template generated by %s --fix from %s — secret values removed.\n", APPNAME, src)
	for i := 0; i < len(lines); i++ {
		e, ok := byLine[i+1]
		if !ok {
			b.WriteString(lines[i] + "\n")
			continue
		}
		i += strings.Count(e.raw, "\n")
		if e.hasKV {
			fmt.Fprintf(&b, "%s=%s\n", e.key, templateValue(e.key, e.val))
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func printFixes(fx []fixAction, apply bool) (applied, failed int) {
	sectionHeader("Fix")
	if len(fx) == 0 {
		okMsg("Nothing to fix automatically.")
		return
	}
	for _, a := range fx {
		switch {
		case a.manual:
			fmt.Println("  " + col("[!] ", OR+B) + col("manual  ", OR) + col(a.desc, W))
		case !apply:
			fmt.Println("  " + col("[*] ", CY) + col("plan    ", CY) + col(a.desc, W))
		default:
			if err := a.do(); err != nil {
				failed++
				fmt.Println("  " + col("[✘] ", R+B) + col(a.desc+": "+err.Error(), R))
			} else {
				applied++
				fmt.Println("  " + col("[✔] ", GRN+B) + col(a.desc, W))
			}
		}
	}
	if !apply {
		fmt.Println()
		info("dry run — nothing changed")
	}
	return
}

// ====================================================================
//  DEMO + SELF-TEST
// ====================================================================

// demo tokens are assembled at runtime so this source never contains a
// string that secret scanners (or GitHub push protection) would flag.
func demoFiles() map[string]string {
	gh := "ghp" + "_" + "Zq8" + strings.Repeat("Lm4Tv9Wx2", 4)
	stripe := "sk_" + "live_" + "51Hx" + strings.Repeat("Qp7Rt", 5)
	aws := "AKIA" + "Q3R7" + "W2LMN5XY4TZ6"
	jwtH := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	jwtP := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"svc-backup","role":"admin"}`))
	jwt := jwtH + "." + jwtP + ".c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
	return map[string]string{
		".env": "# production settings\n" +
			"APP_ENV=production\nDEBUG=true\n" +
			"DATABASE_URL=postgres://app:Tr0ub4dor-77@db.internal:5432/app?sslmode=disable\n" +
			"export SECRET_KEY=\"9f3b6c1e8a2d4f70b5c9e1a3d7f20b4c\"  # signing key\n" +
			"ADMIN_PASSWORD=changeme\n" +
			"GITHUB_TOKEN=" + gh + "\n" +
			"STRIPE_SECRET=" + stripe + "\n" +
			"AWS_ACCESS_KEY_ID=" + aws + "\n" +
			"SESSION_TOKEN=" + jwt + "\n" +
			"BACKUP_SECRET=9f3b6c1e8a2d4f70b5c9e1a3d7f20b4c\n" +
			"NODE_TLS_REJECT_UNAUTHORIZED=0\n" +
			"CORS_ALLOWED_ORIGINS=*\n" +
			"PASSWORD_MIN_LENGTH=12\nTOKEN_EXPIRY=3600\n" +
			"REDIS_PASSWORD=${REDIS_PASSWORD}\n" +
			"DEBUG=false\n",
		".env.example": "APP_ENV=development\nDEBUG=false\n" +
			"DATABASE_URL=postgres://user:password@localhost:5432/app\n" +
			"SECRET_KEY=your-secret-key\nADMIN_PASSWORD=changeme\n" +
			"GITHUB_TOKEN=\nSTRIPE_SECRET=sk_test_xxx\nSENTRY_DSN=\n" +
			"MAILER_API_KEY=k3Vq9ZtR2mXp7LwB4nYc\n",
	}
}

func runDemo() (Report, []string, error) {
	dir, err := os.MkdirTemp("", "oenvscan-demo-")
	if err != nil {
		return Report{}, nil, err
	}
	defer os.RemoveAll(dir)
	for name, body := range demoFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return Report{}, nil, err
		}
	}
	s := newScanner()
	if err := s.ScanTree(dir); err != nil {
		return Report{}, nil, err
	}
	rep := s.Finish("demo project (synthetic, temp dir)", SevInfo)
	for i := range rep.Findings {
		rep.Findings[i].File = strings.TrimPrefix(rep.Findings[i].File, dir+string(os.PathSeparator))
	}
	return rep, s.warns, nil
}

type selfCase struct {
	name, file, body string
	want             string // rule ID that must fire ("" = no findings ≥ LOW)
	sev              string // expected severity of that rule ("" = any)
	absent           string // rule ID that must NOT fire
}

func selfCases() []selfCase {
	gh := "ghp" + "_" + strings.Repeat("aB3dE5fG7h", 4)
	ant := "sk-" + "ant-api03-" + strings.Repeat("Ab1Cd2Ef3Gh4", 8)
	oai := "sk-" + "proj-" + strings.Repeat("Qw9Er8Ty7U", 5)
	return []selfCase{
		{"aws key id", ".env", "AWS_ACCESS_KEY_ID=AKIA" + "Q3R7W2LMN5XY4TZ6", "ENV-AWS-KEY", SevHigh, ""},
		{"aws doc example downgraded", ".env", "AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE", "ENV-AWS-KEY", SevInfo, ""},
		{"weak default", ".env", "ADMIN_PASSWORD=changeme", "ENV-WEAK", SevHigh, ""},
		{"length setting not a secret", ".env", "PASSWORD_MIN_LENGTH=8", "", "", "ENV-SHORT"},
		{"expiry not a secret", ".env", "TOKEN_EXPIRY=3600", "", "", "ENV-SHORT"},
		{"email verify not TLS", ".env", "EMAIL_VERIFY_REQUIRED=false", "", "", "ENV-TLS-OFF"},
		{"node tls off", ".env", "NODE_TLS_REJECT_UNAUTHORIZED=0", "ENV-TLS-OFF", SevHigh, ""},
		{"export + quotes + comment", ".env", `export DB_PASSWORD="Vx8#qL2!mZ7@pR4$" # prod`, "ENV-HARDCODED", SevMedium, ""},
		{"variable reference skipped", ".env", "API_KEY=${API_KEY}", "", "", "ENV-SHORT"},
		{"template real secret", ".env.example", "MAILER_API_KEY=k3Vq9ZtR2mXp7LwB4nYc", "ENV-EXAMPLE-SECRET", SevHigh, ""},
		{"template placeholder ok", ".env.example", "API_KEY=your-api-key\nSECRET=changeme", "", "", "ENV-WEAK"},
		{"url credentials", ".env", "DATABASE_URL=postgres://app:Tr0ub4dor77@db:5432/x", "ENV-URL-CREDS", SevHigh, ""},
		{"url placeholder password", ".env", "DATABASE_URL=postgres://app:${DB_PASS}@db/x", "ENV-URL-CREDS", SevInfo, ""},
		{"multiline private key", ".env", "TLS_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\"", "ENV-PRIVATE-KEY", SevCritical, ""},
		{"duplicate key", ".env", "PORT=1\nPORT=2", "ENV-DUP-KEY", SevLow, ""},
		{"debug on", ".env", "DEBUG=true", "ENV-DEBUG", SevMedium, ""},
		{"debug toolbar port", ".env", "DEBUG_TOOLBAR_PORT=1", "", "", "ENV-DEBUG"},
		{"git sha not secret", ".env", "GIT_COMMIT=3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a", "", "", "ENV-HARDCODED"},
		{"cors wildcard", ".env", "CORS_ORIGINS=*", "ENV-CORS", SevMedium, ""},
		{"github token", ".env", "GH=" + gh, "ENV-GITHUB-TOKEN", SevHigh, ""},
		{"anthropic key", ".env", "KEY_A=" + ant, "ENV-ANTHROPIC-KEY", SevHigh, "ENV-OPENAI-KEY"},
		{"openai key", ".env", "KEY_B=" + oai, "ENV-OPENAI-KEY", SevHigh, ""},
		{"camelCase json secret", "appsettings.json", `  "clientSecret": "Zr8pQ2vX9mL4tK7wB1nC",`, "ENV-HARDCODED", SevMedium, ""},
		{"netrc password", ".netrc", "machine api.example.com login bob password Hn4!xQ9zLp2v", "ENV-HARDCODED", SevMedium, ""},
		{"wp-config define", "wp-config.php", "define( 'DB_PASSWORD', 'admin123' );", "ENV-WEAK", SevHigh, ""},
		{"short secret", ".env", "JWT_SECRET=abc1x", "ENV-SHORT", SevMedium, ""},
		{"low entropy secret", ".env", "SESSION_SECRET=aaaaabbbbbaaaaabbbbb1", "ENV-LOW-ENTROPY", SevMedium, ""},
		{"pem header without body", "detector.yml", `pattern: "-----BEGIN PRIVATE KEY-----"`, "ENV-PRIVATE-KEY", SevInfo, ""},
		{"json-escaped pem body", "sa.json", `"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",`, "ENV-PRIVATE-KEY", SevCritical, ""},
		{"default-credential wordlist", "creds.json", strings.Repeat("  \"username\": \"admin\",\n  \"password\": \"admin\",\n", 6), "ENV-WEAK-LIST", SevLow, "ENV-WEAK"},
		{"shell PWD is a path", ".env", "PWD=/home/user/project\nOLDPWD=/tmp", "", "", "ENV-HARDCODED"},
		{"db ssl disabled", ".env", "PGURL=postgres://db.internal/app?sslmode=disable", "ENV-DB-SSL-OFF", SevLow, ""},
		{"entropy: random blob, plain key", ".env", "SERVICE_BLOB=Qx7Lp2Vz9Kd4Rt8Wm3Ny6Hb", "ENV-ENTROPY", SevMedium, ""},
		{"entropy: long hex", "config.yml", "upstream: 9f3b6c1e8a2d4f70b5c9e1a3d7f20b4c", "ENV-ENTROPY", SevLow, ""},
		{"entropy: uuid ignored", ".env", "TENANT=3f2a9c1e-7b4d-4e8a-9c2f-1a3b5c7d9e0f", "", "", "ENV-ENTROPY"},
		{"entropy: image digest ignored", ".env", "IMAGE_DIGEST=Qx7Lp2Vz9Kd4Rt8Wm3Ny6Hb", "", "", "ENV-ENTROPY"},
		{"entropy: words ignored", ".env", "GREETING=HelloWorldFromTheApp", "", "", "ENV-ENTROPY"},
		{"inline oenvscan:ignore", ".env", "API_TOKEN=Zr8pQ2vX9mL4tK7wB1nC # oenvscan:ignore", "", "", "ENV-HARDCODED"},
	}
}

func hasRule(fs []Finding, id string) (Finding, bool) {
	for _, f := range fs {
		if f.RuleID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func runSelfTest() int {
	var rows [][]string
	fail, total := 0, 0
	check := func(name, expect, got string, ok bool) {
		total++
		res := col("PASS", GRN+B)
		if !ok {
			res = col("FAIL", R+B)
			fail++
		}
		rows = append(rows, []string{trunc(name, 30), trunc(expect, 26), trunc(got, 30), res})
	}
	for _, c := range selfCases() {
		s := newScanner()
		fs := s.scanContent(c.file, []byte(c.body), kindOf(c.file), isTemplate(c.file))
		var got []string
		for _, f := range fs {
			got = append(got, f.RuleID+"/"+f.Severity)
		}
		ok := true
		expect := "none"
		if c.want != "" {
			f, hit := hasRule(fs, c.want)
			ok = hit && (c.sev == "" || f.Severity == c.sev)
			expect = c.want + "/" + c.sev
		} else {
			for _, f := range fs {
				if sevRank[f.Severity] >= sevRank[SevLow] {
					ok = false
				}
			}
		}
		if c.absent != "" {
			if _, hit := hasRule(fs, c.absent); hit {
				ok = false
			}
		}
		g := strings.Join(got, ",")
		if g == "" {
			g = "none"
		}
		check(c.name, expect, g, ok)
	}

	// reuse across keys
	s := newScanner()
	s.findings = append(s.findings, s.scanContent(".env", []byte("A_SECRET=Kp9zW2xQ7vL4mN8r\nB_TOKEN=Kp9zW2xQ7vL4mN8r"), kindEnv, false)...)
	rep := s.Finish("t", SevInfo)
	_, hit := hasRule(rep.Findings, "ENV-REUSE")
	check("secret reuse across keys", "ENV-REUSE", fmt.Sprint(hit), hit)

	// drift + perms + git, on real temp files
	dir, err := os.MkdirTemp("", "oenvscan-test-")
	if err == nil {
		defer os.RemoveAll(dir)
		os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nAPI_TOKEN=Zr8pQ2vX9mL4tK7wB1nC\n"), 0o644)
		os.WriteFile(filepath.Join(dir, ".env.example"), []byte("A=\nB=\n"), 0o644)
		s := newScanner()
		s.ScanTree(dir)
		_, m := hasRule(s.findings, "ENV-DRIFT-MISSING")
		_, u := hasRule(s.findings, "ENV-DRIFT-UNDOC")
		check("env/example drift", "MISSING+UNDOC", fmt.Sprint(m, u), m && u)
		_, pw := hasRule(s.findings, "ENV-PERM-WORLD")
		check("world-readable secrets file", "ENV-PERM-WORLD", fmt.Sprint(pw), pw)
		if bin, err := exec.LookPath("git"); err == nil {
			cmd := func(a ...string) error {
				c := exec.Command(bin, append([]string{"-C", dir}, a...)...)
				c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
				return c.Run()
			}
			if cmd("init", "-q") == nil {
				s := newScanner()
				s.ScanFile(filepath.Join(dir, ".env"))
				_, un := hasRule(s.findings, "ENV-GIT-UNIGNORED")
				check("git: not ignored", "ENV-GIT-UNIGNORED", fmt.Sprint(un), un)
				cmd("add", "-f", ".env")
				s = newScanner()
				s.ScanFile(filepath.Join(dir, ".env"))
				f, tr := hasRule(s.findings, "ENV-GIT-TRACKED")
				check("git: committed secrets", "ENV-GIT-TRACKED/CRITICAL", f.Severity, tr && f.Severity == SevCritical)
			}
		}
	}
	selfTestExtras(check)
	table([]string{"CASE", "EXPECT", "GOT", "RESULT"}, rows)
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("self-test: %d/%d passed", total, total))
	} else {
		errMsg(fmt.Sprintf("self-test: %d/%d FAILED", fail, total))
	}
	return fail
}

// selfTestExtras covers the stateful features: ignore files, baselines,
// git history and --fix, each on a throw-away temp directory.
func selfTestExtras(check func(name, expect, got string, ok bool)) {
	dir, err := os.MkdirTemp("", "oenvscan-x-")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)
	envp := filepath.Join(dir, ".env")
	os.WriteFile(envp, []byte("DEBUG=true\nAPI_TOKEN=Zr8pQ2vX9mL4tK7wB1nC\nPORT=8080\n"), 0o644)
	scan := func(sp *suppressor) Report {
		s := newScanner()
		s.sup = sp
		s.ScanFile(envp)
		return s.Finish("t", SevInfo)
	}

	// ignore file: rule id + RULE:glob
	ig := filepath.Join(dir, "ign")
	os.WriteFile(ig, []byte("# accepted\nENV-DEBUG\nENV-PERM-WORLD:*.env\n"), 0o600)
	sp := &suppressor{}
	sp.loadIgnore(ig)
	r := scan(sp)
	_, d := hasRule(r.Findings, "ENV-DEBUG")
	_, h := hasRule(r.Findings, "ENV-HARDCODED")
	check("ignore file: rule + glob", "DEBUG hidden, secret kept", fmt.Sprint(!d, h, r.Suppressed), !d && h && r.Suppressed >= 1)

	// baseline: everything known is hidden; a new secret still shows
	base := filepath.Join(dir, "base.json")
	writeBaseline(scan(nil), base)
	os.WriteFile(envp, []byte("# moved down\nDEBUG=true\nAPI_TOKEN=Zr8pQ2vX9mL4tK7wB1nC\nPORT=8080\nDB_PASSWORD=Vx8qL2mZ7pR4tW9k\n"), 0o644)
	sp = &suppressor{}
	sp.loadBaseline(base)
	r = scan(sp)
	var ids []string
	for _, f := range r.Findings {
		ids = append(ids, f.RuleID+":"+f.Key)
	}
	ok := len(r.Findings) == 1 && r.Findings[0].Key == "DB_PASSWORD"
	check("baseline: only new finding", "DB_PASSWORD only", strings.Join(ids, ","), ok)

	// fix: chmod, template, .gitignore
	r = scan(nil)
	for _, a := range planFixes(r) {
		if a.do != nil {
			a.do()
		}
	}
	fi, _ := os.Stat(envp)
	tmpl, _ := os.ReadFile(filepath.Join(dir, ".env.example"))
	ok = fi.Mode().Perm() == 0o600 && strings.Contains(string(tmpl), "API_TOKEN=\n") &&
		strings.Contains(string(tmpl), "PORT=8080") && !strings.Contains(string(tmpl), "Zr8pQ2")
	check("fix: chmod 600 + template", "0600, secrets blanked", fmt.Sprintf("%04o", fi.Mode().Perm()), ok)

	bin, err := exec.LookPath("git")
	if err != nil {
		return
	}
	gdir := filepath.Join(dir, "repo")
	os.Mkdir(gdir, 0o755)
	git := func(a ...string) error {
		c := exec.Command(bin, append([]string{"-C", gdir}, a...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		return c.Run()
	}
	if git("init", "-q") != nil {
		return
	}
	gh := "ghp" + "_" + strings.Repeat("kT4mW8qZ2x", 4)
	os.WriteFile(filepath.Join(gdir, ".env"), []byte("APP=x\nGITHUB_TOKEN="+gh+"\n"), 0o600)
	os.WriteFile(filepath.Join(gdir, "main.go"), []byte("package main\n// token "+gh+"\n"), 0o644)
	git("add", "-A")
	git("commit", "-qm", "init")
	git("rm", "-q", ".env")
	os.WriteFile(filepath.Join(gdir, "main.go"), []byte("package main\n"), 0o644)
	git("add", "-A")
	git("commit", "-qm", "remove secrets")
	s := newScanner()
	n, err := s.ScanHistory(gdir)
	cnt, removed := 0, 0
	for _, f := range s.findings {
		if f.RuleID == "ENV-GIT-HISTORY" {
			cnt++
			if strings.Contains(f.Detail, "every clone") {
				removed++
			}
		}
	}
	check("git history: deleted secrets", "2 hits, both gone from HEAD", fmt.Sprintf("commits=%d hits=%d gone=%d", n, cnt, removed),
		err == nil && cnt == 2 && removed == 2)
}

// ====================================================================
//  INTERACTIVE TUI
// ====================================================================

var lastReport *Report

type tuiAction struct {
	name, desc string
	fn         func()
}

var tuiActions []tuiAction

func init() {
	tuiActions = []tuiAction{
		{"Scan a file", "secrets · misconfig · perms · git", uiScanFile},
		{"Scan a directory tree", "find every env / credential file", uiScanTree},
		{"Scan this process env", "variables inherited by this shell", uiScanEnv},
		{"Scan running processes", "/proc/<pid>/environ you can read", uiScanProcs},
		{"Scan git history", "secrets in past commits, even deleted", uiHistory},
		{"Compare .env ↔ template", "missing / undocumented keys", uiDrift},
		{"Token / entropy check", "strength + provider format", uiToken},
		{"Rule catalog", "every rule, severity and fix", uiCatalog},
		{"Fix last scan", "chmod · .gitignore · sanitised template", uiFix},
		{"Save baseline", "accept last scan's findings for CI", uiBaseline},
		{"Export last report", "txt · md · json · csv · sarif", uiExport},
		{"Run demo", "synthetic project in a temp dir", uiDemo},
		{"Self-test", "built-in detection regression suite", uiSelfTest},
	}
}

func mainMenu() {
	for {
		clear()
		banner()
		fmt.Println("  " + col("⬡  Main Menu", B+CY))
		fmt.Println()
		for i, a := range tuiActions {
			fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
				col(pad(a.name, 26), W) + col("─ "+a.desc, DIM))
		}
		fmt.Println()
		fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 26), W) + col("─ How to use, every option, CLI flags & examples", DIM))
		fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 26), W) + col("─ Quit "+APPNAME, DIM))
		fmt.Println()
		rule()
		c := strings.TrimLeft(prompt("Select option"), "0")
		if c == "" {
			clear()
			okMsg("Goodbye.")
			return
		}
		if strings.EqualFold(c, "h") || strings.EqualFold(c, "help") || c == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(c)
		if err != nil || n < 1 || n > len(tuiActions) {
			errMsg("Unknown option")
			pause()
			continue
		}
		clear()
		banner()
		tuiActions[n-1].fn()
		pause()
	}
}

// finishUI applies any .oenvscanignore found next to the scanned roots.
func finishUI(s *scanner, target string, roots ...string) {
	if sp, err := loadSuppressor(roots, "", ""); err == nil && sp != nil {
		s.sup = sp
		info("ignore rules: " + strings.Join(sp.sources, ", "))
	}
	rep := s.Finish(target, SevInfo)
	lastReport = &rep
	printReport(rep, s.warns)
}

func uiScanFile() {
	sectionHeader("Scan a File")
	p := prompt("file path")
	if p == "" {
		return
	}
	s := newScanner()
	if err := s.ScanFile(p); err != nil {
		errMsg(err.Error())
		return
	}
	finishUI(s, p, p)
}

func uiScanTree() {
	sectionHeader("Scan a Directory Tree")
	root := prompt("directory (blank = .)")
	if root == "" {
		root = "."
	}
	s := newScanner()
	info("walking " + root + " …")
	if err := s.ScanTree(root); err != nil {
		errMsg(err.Error())
		return
	}
	finishUI(s, root, root)
}

func uiHistory() {
	sectionHeader("Scan Git History")
	root := prompt("repository path (blank = .)")
	if root == "" {
		root = "."
	}
	if v := prompt(fmt.Sprintf("max commits (blank = %d, 0 = all)", historyMax)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			historyMax = n
		}
	}
	s := newScanner()
	info("reading git log -p …")
	n, err := s.ScanHistory(root)
	if err != nil {
		errMsg(err.Error())
		return
	}
	finishUI(s, fmt.Sprintf("git history of %s (%d commits)", root, n), root)
}

func uiFix() {
	sectionHeader("Fix Last Scan")
	if lastReport == nil {
		warnMsg("Run a scan first.")
		return
	}
	fx := planFixes(*lastReport)
	printFixes(fx, false)
	auto := 0
	for _, a := range fx {
		if !a.manual {
			auto++
		}
	}
	if auto == 0 {
		return
	}
	fmt.Println()
	if a := strings.ToLower(prompt(fmt.Sprintf("apply %d change(s)? [y/N]", auto))); a != "y" && a != "yes" {
		info("nothing changed")
		return
	}
	fmt.Println()
	printFixes(fx, true)
}

func uiBaseline() {
	sectionHeader("Save Baseline")
	if lastReport == nil {
		warnMsg("Run a scan first.")
		return
	}
	out := prompt("baseline file (blank = .oenvscan-baseline.json)")
	if out == "" {
		out = ".oenvscan-baseline.json"
	}
	if err := writeBaseline(*lastReport, out); err != nil {
		errMsg(err.Error())
		return
	}
	okMsg(fmt.Sprintf("%d finding(s) baselined → %s", len(lastReport.Findings), out))
	info("use it with: OEnvScan --baseline " + out + " PATH")
}

func uiScanEnv() {
	sectionHeader("Scan This Process Environment")
	s := newScanner()
	s.ScanEnviron("environ", os.Environ())
	finishUI(s, fmt.Sprintf("process environment (%d vars)", len(os.Environ())))
}

func uiScanProcs() {
	sectionHeader("Scan Running Processes")
	s := newScanner()
	n, err := s.ScanProcs()
	if err != nil {
		errMsg(err.Error())
		return
	}
	finishUI(s, fmt.Sprintf("/proc environ of %d readable processes", n))
}

func uiDrift() {
	sectionHeader("Compare .env ↔ Template")
	e := prompt(".env path")
	t := prompt("template path (blank = .env.example next to it)")
	if t == "" {
		t = filepath.Join(filepath.Dir(e), ".env.example")
	}
	if _, err := os.Stat(e); err != nil {
		errMsg(err.Error())
		return
	}
	if _, err := os.Stat(t); err != nil {
		errMsg(err.Error())
		return
	}
	s := newScanner()
	s.files = 2
	s.findings = compareDrift(e, t)
	finishUI(s, e+" ↔ "+t)
}

func uiToken() {
	sectionHeader("Token / Entropy Check")
	v := prompt("value to assess (not stored)")
	if v == "" {
		return
	}
	t := assessToken(v)
	fmt.Println()
	kv("Length", strconv.Itoa(t.length))
	kv("Charset", fmt.Sprintf("%d symbols", t.charset))
	kv("Entropy", fmt.Sprintf("%.3f bits/char", t.entropy))
	kv("Strength", fmt.Sprintf("%.0f bits  %s", t.bits, entropyBar(t.bits)))
	kv("Verdict", sevColor(t.severity)+"  "+col(t.verdict, W))
}

func uiCatalog() {
	sectionHeader("Rule Catalog")
	var rows [][]string
	for _, r := range ruleCatalog {
		rows = append(rows, []string{r.ID, sevColor(r.Sev), trunc(r.Title, 40)})
	}
	table([]string{"RULE", "SEV", "TITLE"}, rows)
	fmt.Println()
	info("Context escalates findings: committed to git → CRITICAL, world-readable → HIGH,")
	info("real secrets inside .env.example / templates → at least HIGH.")
}

func uiExport() {
	sectionHeader("Export Last Report")
	if lastReport == nil {
		warnMsg("Run a scan first.")
		return
	}
	f := prompt("format [txt|md|json|csv|sarif]")
	out := prompt("output file (blank = stdout)")
	s, err := render(*lastReport, f)
	if err != nil {
		errMsg(err.Error())
		return
	}
	if err := writeOut(s, out); err != nil {
		errMsg(err.Error())
		return
	}
	if out != "" {
		okMsg("wrote " + out + " (mode 0600)")
	}
}

func uiDemo() {
	sectionHeader("Demo — synthetic project")
	rep, warns, err := runDemo()
	if err != nil {
		errMsg(err.Error())
		return
	}
	lastReport = &rep
	printReport(rep, warns)
}

func uiSelfTest() {
	sectionHeader("Self-Test")
	runSelfTest()
}

// ====================================================================
//  CLI
// ====================================================================

func usage() {
	banner()
	fmt.Print(`USAGE:
  OEnvScan [flags] [PATH ...]

  PATH may be files or directories (directories are walked for .env,
  .npmrc, .pypirc, .netrc, .git-credentials, *.tfvars, appsettings*.json,
  application*.properties, docker-compose.yml, ~/.aws/credentials …).
  With no PATH and no --env/--proc/--demo, the interactive TUI starts.

FLAGS:
  --env              Scan this process's environment
  --proc             Scan /proc/<pid>/environ of every readable process
  --format FMT       txt | md | json | csv | sarif   (default: coloured TUI report)
  --output FILE      Write the report to FILE (mode 0600)
  --min-sev SEV      Hide findings below SEV (INFO|LOW|MEDIUM|HIGH|CRITICAL)
  --exclude PATTERN  Skip paths matching PATTERN (glob on name, or substring); repeatable
  --max-size BYTES   Skip files larger than this (default 4194304)
  --show-secrets     Print raw secret values instead of masked ones
  --no-git           Do not query git for tracked / ignored state

HISTORY & ENTROPY:
  --git-history      Also scan every commit of the repo (git log -p), incl. deleted secrets
  --history-max N    Commits to read (default 1000, 0 = all)
  --entropy-min F    Bits/char for the generic high-entropy rule (default 4.0)
  --no-entropy       Disable the generic high-entropy rule

BASELINE & IGNORE:
  --baseline FILE    Hide findings recorded in FILE (baseline or JSON report)
  --write-baseline FILE  Record the current findings as accepted
  --ignore-file FILE Extra ignore file (.oenvscanignore is picked up automatically)
                     lines: RULE-ID · path/glob · RULE-ID:glob · fp:<fingerprint>
                     inline: append "# oenvscan:ignore" to a line

FIX:
  --fix              Apply safe fixes: chmod 600, add to .gitignore, write a
                     sanitised .env.example where none exists
  --dry-run          With --fix: show the plan, change nothing

OTHER:
  --demo             Scan a synthetic demo project
  --selftest         Run the detection regression suite
  --no-color         Disable colours
  --version          Print version

EXIT CODES:
  0 clean (nothing HIGH or above) · 1 error · 3 HIGH/CRITICAL findings present

EXAMPLES:
  OEnvScan .
  OEnvScan --format sarif --output envscan.sarif ~/projects/api
  OEnvScan --proc --min-sev MEDIUM
  OEnvScan --env --format json | jq '.findings[].rule_id'
  OEnvScan --git-history --history-max 0 .
  OEnvScan . --write-baseline .oenvscan-baseline.json     # once
  OEnvScan . --baseline .oenvscan-baseline.json           # in CI: new findings only
  OEnvScan . --fix --dry-run
`)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// parseInterleaved lets flags appear before or after positional paths.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func main() {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.Usage = usage
	var excludes multiFlag
	fEnv := fs.Bool("env", false, "")
	fProc := fs.Bool("proc", false, "")
	fFormat := fs.String("format", "", "")
	fOutput := fs.String("output", "", "")
	fMinSev := fs.String("min-sev", "INFO", "")
	fMaxSize := fs.Int64("max-size", 4<<20, "")
	fShow := fs.Bool("show-secrets", false, "")
	fNoGit := fs.Bool("no-git", false, "")
	fDemo := fs.Bool("demo", false, "")
	fSelf := fs.Bool("selftest", false, "")
	fNoColor := fs.Bool("no-color", false, "")
	fVersion := fs.Bool("version", false, "")
	fHistory := fs.Bool("git-history", false, "")
	fHistMax := fs.Int("history-max", historyMax, "")
	fEntMin := fs.Float64("entropy-min", entropyMin, "")
	fNoEnt := fs.Bool("no-entropy", false, "")
	fBaseline := fs.String("baseline", "", "")
	fWriteBase := fs.String("write-baseline", "", "")
	fIgnore := fs.String("ignore-file", "", "")
	fFix := fs.Bool("fix", false, "")
	fDry := fs.Bool("dry-run", false, "")
	fs.Var(&excludes, "exclude", "")
	paths, err := parseInterleaved(fs, os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(1)
	}
	if *fNoColor {
		noColor = true
	}
	showSecrets = *fShow
	useGit = !*fNoGit
	historyMax, entropyMin, entropyOn = *fHistMax, *fEntMin, !*fNoEnt
	if *fVersion {
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, TAGLINE)
		return
	}
	if *fSelf {
		if runSelfTest() != 0 {
			os.Exit(1)
		}
		return
	}
	minSev := strings.ToUpper(*fMinSev)
	if _, ok := sevRank[minSev]; !ok {
		errMsg("unknown --min-sev " + *fMinSev)
		os.Exit(1)
	}
	if *fHistory && len(paths) == 0 {
		paths = []string{"."}
	}
	if len(paths) == 0 && !*fEnv && !*fProc && !*fDemo {
		mainMenu()
		return
	}

	var rep Report
	var warns []string
	if *fDemo {
		rep, warns, err = runDemo()
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
	} else {
		s := newScanner()
		s.maxSize = *fMaxSize
		s.excludes = excludes
		sp, err := loadSuppressor(paths, *fIgnore, *fBaseline)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		s.sup = sp
		var targets []string
		for _, p := range paths {
			if err := s.ScanFile(p); err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			targets = append(targets, p)
		}
		if *fHistory {
			repos := map[string]bool{}
			for _, p := range paths {
				probe := p
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					probe = filepath.Join(p, "_")
				}
				r := gitRoot(probe)
				if r == "" || repos[r] {
					continue
				}
				repos[r] = true
				n, err := s.ScanHistory(p)
				if err != nil {
					errMsg(err.Error())
					os.Exit(1)
				}
				targets = append(targets, fmt.Sprintf("git history of %s (%d commits)", relPath(r), n))
			}
			if len(repos) == 0 {
				warnMsg("--git-history: no git repository found under the given paths")
			}
		}
		if *fEnv {
			s.ScanEnviron("environ", os.Environ())
			targets = append(targets, "environ")
		}
		if *fProc {
			n, err := s.ScanProcs()
			if err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			targets = append(targets, fmt.Sprintf("/proc (%d processes)", n))
		}
		rep = s.Finish(strings.Join(targets, ", "), minSev)
		warns = s.warns
	}
	if *fDemo && minSev != SevInfo {
		var keep []Finding
		for _, f := range rep.Findings {
			if sevRank[f.Severity] >= sevRank[minSev] {
				keep = append(keep, f)
			}
		}
		if keep == nil {
			keep = []Finding{}
		}
		rep.Findings = keep
	}

	if *fWriteBase != "" {
		if err := writeBaseline(rep, *fWriteBase); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "baseline: %d finding(s) recorded in %s\n", len(rep.Findings), *fWriteBase)
	}
	if *fFormat == "" && *fOutput == "" {
		banner()
		printReport(rep, warns)
		if *fFix {
			fmt.Println()
			printFixes(planFixes(rep), !*fDry)
		}
	} else {
		out, err := render(rep, *fFormat)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if err := writeOut(out, *fOutput); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, "warning: "+w)
		}
		if *fFix {
			for _, a := range planFixes(rep) {
				switch {
				case a.manual:
					fmt.Fprintln(os.Stderr, "fix (manual): "+a.desc)
				case *fDry:
					fmt.Fprintln(os.Stderr, "fix (plan): "+a.desc)
				case a.do() != nil:
					fmt.Fprintln(os.Stderr, "fix FAILED: "+a.desc)
				default:
					fmt.Fprintln(os.Stderr, "fixed: "+a.desc)
				}
			}
		}
	}
	if rep.Counts[SevCritical]+rep.Counts[SevHigh] > 0 {
		os.Exit(3)
	}
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OEnvScan finds leaked secrets and risky settings in .env files and other environment / credential files: API keys, cloud credentials, database URLs with passwords, private keys, JWT secrets and more. It recognises provider formats (AWS, GitHub, Stripe, Slack, Google ...) and also flags random-looking high-entropy values.",
	"Besides secrets it checks file permissions (world-readable), whether the file is committed to git or missing from .gitignore, debug / insecure settings, and secrets that are still in old git commits even after they were deleted. Secret values are masked in the output.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Scans are [1] to [5]. Options [9], [10] and [11] then work on the last scan. [H] opens this help, [0] or a blank line quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Scan a file: enter the path of one file, e.g. .env, config.yml or docker-compose.yml."},
	{"2", "Scan a directory tree: enter a folder (blank = current folder). Finds and scans every env / credential file under it."},
	{"3", "Scan this process env: checks the environment variables this shell passed to OEnvScan."},
	{"4", "Scan running processes: reads /proc/<pid>/environ of every process you are allowed to read (run as root to see all)."},
	{"5", "Scan git history: enter the repository path (blank = .) and how many commits to check (0 = all). Finds secrets that were committed in the past, even if deleted since. Those secrets must be rotated."},
	{"6", "Compare .env ↔ template: enter the .env path and its template (blank = .env.example next to it). Lists keys missing from either side."},
	{"7", "Token / entropy check: paste one value. Shows its entropy, strength and which provider format it matches. The value is not stored."},
	{"8", "Rule catalog: every detection rule with its severity and how to fix it."},
	{"9", "Fix last scan: shows the safe fixes (chmod 600, add to .gitignore, write a sanitised .env.example) and asks y/N before changing anything."},
	{"10", "Save baseline: saves the last scan's findings as accepted (blank = .oenvscan-baseline.json). In CI, --baseline then reports only NEW findings."},
	{"11", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"12", "Run demo: creates a sample project in a temp folder and scans it."},
	{"13", "Self-test: the built-in detection regression suite."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "To silence a false positive, add  # oenvscan:ignore  at the end of that line, or put it in a .oenvscanignore file."},
	{"*", "A secret that was ever committed is compromised. Removing it from the file is not enough: rotate it."},
	{"*", "--show-secrets prints the real values instead of masked ones. Avoid it on shared screens and in CI logs."},
}

func owlHelpCLI() { usage() }
