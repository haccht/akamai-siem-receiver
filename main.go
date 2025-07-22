package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	WAFConfigID     string        `short:"c" long:"config" description:"WAF Config ID" required:"true"`
	Offset          string        `long:"offset" description:"Token that denotes the last message" default:"NULL"`
	Limit           int           `long:"limit" description:"The approximate maximum number of security events each fetch returns" default:"10000"`
	Follow          bool          `short:"f" long:"follow" description:"Continue retrieving messages"`
	Interval        time.Duration `short:"i" long:"interval" description:"Interval of message retrieval" default:"5m"`
	EdgeGridFile    string        `short:"r" long:"file" description:"Location of EdgeGrid file" default:"~/.edgerc"`
	EdgeGridSection string        `short:"s" long:"section" description:"Section of EdgeGrid file" default:"default"`
	Host            string        `long:"host" env:"EDGEGRID_HOST" description:"EdgeGrid Host"`
	ClientToken     string        `long:"client-token" env:"EDGEGRID_CLIENT_TOKEN" description:"EdgeGrid ClientToken"`
	ClientSecret    string        `long:"client-secret" env:"EDGEGRID_CLIENT_SECRET" description:"EdgeGrid ClientSecret"`
	AccessToken     string        `long:"access-token" env:"EDGEGRID_ACCESS_TOKEN" description:"EdgeGrid AccessToken"`
}

type SIEMRecord struct {
	AttackData   AttackData   `json:"attackData"`
	BotData      BotData      `json:"botData"`
	ClientData   ClientData   `json:"clientData"`
	Format       string       `json:"format"`
	Geo          Geo          `json:"geo"`
	HTTPMessage  HTTPMessage  `json:"httpMessage"`
	Type         string       `json:"type"`
	UserRiskData UserRiskData `json:"userRiskData"`
	Version      string       `json:"version"`
}

type AttackData struct {
	ClientIP      string      `json:"clientIP"`
	ConfigID      string      `json:"configId"`
	PolicyID      string      `json:"policyId"`
	RuleActions   B64URLSlice `json:"ruleActions"`
	RuleData      B64URLSlice `json:"ruleData"`
	RuleMessages  B64URLSlice `json:"ruleMessages"`
	RuleSelectors B64URLSlice `json:"ruleSelectors"`
	RuleTags      B64URLSlice `json:"ruleTags"`
	RuleVersions  B64URLSlice `json:"ruleVersions"`
	Rules         B64URLSlice `json:"rules"`
}

type BotData struct {
	BotScore        string `json:"botScore"`
	ResponseSegment string `json:"responseSegment"`
}

type ClientData struct {
	AppBundleID string `json:"appBundleId"`
	AppVersion  string `json:"appVersion"`
	SDKVersion  string `json:"sdkVersion"`
	Telemetry   string `json:"telemetryType"`
}

type Geo struct {
	ASN        string `json:"asn"`
	City       string `json:"city"`
	Continent  string `json:"continent"`
	Country    string `json:"country"`
	RegionCode string `json:"regionCode"`
}

type HTTPMessage struct {
	Bytes           string         `json:"bytes"`
	Host            string         `json:"host"`
	Method          string         `json:"method"`
	Path            string         `json:"path"`
	Port            string         `json:"port"`
	Protocol        string         `json:"protocol"`
	Query           RawQueryString `json:"query"`
	RequestHeaders  HeaderLines    `json:"requestHeaders"`
	RequestID       string         `json:"requestId"`
	ResponseHeaders HeaderLines    `json:"responseHeaders"`
	Start           string         `json:"start"`
	Status          string         `json:"status"`
}

type UserRiskData struct {
	Allow      string `json:"allow"`
	General    string `json:"general"`
	OriginUser string `json:"originUserId"`
	Risk       string `json:"risk"`
	Score      string `json:"score"`
	Status     string `json:"status"`
	Trust      string `json:"trust"`
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
}

type SIEMMetadata struct {
	Offset string `json:"offset"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit,omitempty"`
}

type B64URLString string

type B64URLSlice []string

func (d *B64URLString) UnmarshalJSON(data []byte) error {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}
	unescaped, err := url.QueryUnescape(enc)
	if err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		return err
	}
	*d = B64URLString(string(decoded))
	return nil
}

func (s *B64URLSlice) UnmarshalJSON(data []byte) error {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}
	unescaped, err := url.QueryUnescape(enc)
	if err != nil {
		return err
	}

	parts := strings.Split(unescaped, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		plain, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return err
		}
		out = append(out, string(plain))
	}
	*s = out
	return nil
}

func (d B64URLString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d))
}

func (s B64URLSlice) MarshalJSON() ([]byte, error) {
	//return json.Marshal([]string(s))
	return json.Marshal(strings.Join(s, ";"))
}

type HeaderLines []string

func (h *HeaderLines) UnmarshalJSON(data []byte) error {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}
	plain, err := url.QueryUnescape(enc)
	if err != nil {
		return err
	}

	lines := strings.Split(plain, "\r\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if ln != "" {
			out = append(out, ln)
		}
	}
	*h = out
	return nil
}

func (h HeaderLines) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(h))
}

type RawQueryString string

func (r *RawQueryString) UnmarshalJSON(data []byte) error {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return err
	}
	plain, err := url.QueryUnescape(enc)
	if err != nil {
		return err
	}
	*r = RawQueryString(plain)
	return nil
}

func (r RawQueryString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(r))
}

func getSIEMRecords(opts *Options, edgerc *edgegrid.Config) error {
	q := url.Values{}
	q.Add("offset", opts.Offset)
	q.Add("limit", fmt.Sprintf("%d", opts.Limit))

	u := &url.URL{
		Scheme:   "https",
		Host:     edgerc.Host,
		Path:     fmt.Sprintf("/siem/v1/configs/%s", opts.WAFConfigID),
		RawQuery: q.Encode(),
	}

	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/json")
	edgerc.SignRequest(req)

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("received %d %s\n", res.StatusCode, res.Status)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "")
	enc.SetEscapeHTML(false)

	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		var rec SIEMRecord
		var mdt SIEMMetadata

		line := sc.Bytes()
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		if rec.Type == "akamai_siem" {
			if err := enc.Encode(rec); err != nil {
				continue
			}
		} else {
			err := json.Unmarshal(line, &mdt)
			if err != nil {
				continue
			}

			opts.Offset = mdt.Offset
			if err := enc.Encode(mdt); err != nil {
				continue
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	return nil
}

func run() error {
	var opts Options
	_, err := flags.Parse(&opts)
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	var edgerc *edgegrid.Config
	if _, err := os.Stat(opts.EdgeGridFile); err == nil {
		edgerc, err = edgegrid.New(
			edgegrid.WithFile(opts.EdgeGridFile),
			edgegrid.WithSection(opts.EdgeGridSection),
		)
		if err != nil {
			return err
		}
	} else {
		edgerc, _ = edgegrid.New()
	}

	if opts.Host != "" {
		edgerc.Host = opts.Host
	}
	if opts.ClientToken != "" {
		edgerc.ClientToken = opts.ClientToken
	}
	if opts.ClientSecret != "" {
		edgerc.ClientSecret = opts.ClientSecret
	}
	if opts.AccessToken != "" {
		edgerc.AccessToken = opts.AccessToken
	}

	if err := getSIEMRecords(&opts, edgerc); err != nil {
		return err
	}
	if !opts.Follow {
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := getSIEMRecords(&opts, edgerc); err != nil {
				return err
			}
		case <-sigChan:
			return nil
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
