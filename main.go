package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

type Options struct {
	WAFConfigID     string        `short:"c" long:"config" description:"WAF Config ID" required:"true"`
	Offset          string        `long:"offset" description:"Token that denotes the last message" default:"NULL"`
	Limit           int           `long:"limit" description:"The approximate maximum number of security events each fetch returns" default:"10000"`
	Follow          bool          `short:"f" long:"follow" description:"Continue retrieving messages"`
	Interval        time.Duration `short:"i" long:"interval" description:"Interval of message retrieval" default:"5m"`
	Format          string        `long:"format" description:"Output format (json or cef)" default:"cef"`
	Syslog          string        `long:"syslog" description:"CEF target URL over TCP/UDP (e.g., tcp://127.0.0.1:514 or udp://127.0.0.1:514)"`
	EdgeGridFile    string        `short:"r" long:"file" description:"Location of EdgeGrid file" default:"~/.edgerc"`
	EdgeGridSection string        `short:"s" long:"section" description:"Section of EdgeGrid file" default:"default"`
	Host            string        `long:"host" env:"EDGEGRID_HOST" description:"EdgeGrid Host"`
	ClientToken     string        `long:"client-token" env:"EDGEGRID_CLIENT_TOKEN" description:"EdgeGrid ClientToken"`
	ClientSecret    string        `long:"client-secret" env:"EDGEGRID_CLIENT_SECRET" description:"EdgeGrid ClientSecret"`
	AccessToken     string        `long:"access-token" env:"EDGEGRID_ACCESS_TOKEN" description:"EdgeGrid AccessToken"`
}

func (o *Options) normalize() {
	o.Format = strings.ToLower(o.Format)
}

func (o *Options) validate() error {
	if o.Format != "json" && o.Format != "cef" {
		return fmt.Errorf("unsupported output format: %s", o.Format)
	}
	if o.Syslog != "" && o.Format != "cef" {
		return fmt.Errorf("remote socket output requires --format cef")
	}
	return nil
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
	//return json.Marshal(strings.Join(s, ";"))
	return json.Marshal([]string(s))
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

func buildCEF(rec SIEMRecord) string {
	actions := rec.AttackData.RuleActions
	act := firstFromSlice(actions)
	signatureAction := lastFromSlice(actions)
	severity := deriveSeverity(rec)
	signatureID := firstNonEmpty(signatureAction, rec.AttackData.PolicyID, rec.AttackData.ConfigID, "akamai_siem")
	eventName := eventNameFromAction(signatureAction)
	if eventName == "" {
		eventName = firstNonEmpty(firstFromSlice(rec.AttackData.RuleMessages), "akamai_siem event")
	}

	builder := newCEFBuilder(cefHeader{
		DeviceVendor:  "Akamai",
		DeviceProduct: firstNonEmpty(rec.Type, "akamai_siem"),
		DeviceVersion: firstNonEmpty(rec.Version, "1.0"),
		SignatureID:   signatureID,
		Name:          eventName,
		Severity:      severity,
	})

	builder.add("act", act)
	builder.add("app", normalizedProtocol(rec.HTTPMessage.Protocol))
	appendSourceExtensions(&builder, rec.AttackData.ClientIP)
	appendDestinationExtensions(&builder, rec.HTTPMessage)
	builder.add("requestMethod", rec.HTTPMessage.Method)
	if req := buildRequest(rec.HTTPMessage); req != "" {
		builder.add("request", req)
	}
	if start, ok := parseStartTime(rec.HTTPMessage.Start); ok {
		builder.addInt64("start", start.Unix())
		builder.addInt64("end", start.UnixMilli())
	}

	appendRuleExtensions(&builder, rec)
	appendContextExtensions(&builder, rec)

	return builder.String()
}

func parseStartTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}

	start, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(start, 0), true
}

func buildRequest(msg HTTPMessage) string {
	if msg.Method == "" && msg.Path == "" && msg.Query == "" && msg.Host == "" {
		return ""
	}

	path := msg.Path
	if path == "" {
		path = "/"
	}
	if msg.Query != "" {
		path = fmt.Sprintf("%s?%s", path, msg.Query)
	}

	request := path
	if msg.Host != "" {
		scheme := "http"
		if msg.Port == "443" || strings.HasSuffix(strings.ToLower(msg.Protocol), "https") {
			scheme = "https"
		}
		if msg.Port != "" && msg.Port != "80" && msg.Port != "443" {
			request = fmt.Sprintf("%s://%s:%s%s", scheme, msg.Host, msg.Port, path)
		} else {
			request = fmt.Sprintf("%s://%s%s", scheme, msg.Host, path)
		}
	}

	if msg.Method != "" {
		return strings.TrimSpace(fmt.Sprintf("%s %s", msg.Method, request))
	}

	return request
}

func escapeCEFValue(val string) string {
	escaped := strings.ReplaceAll(val, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "|", "\\|")
	escaped = strings.ReplaceAll(escaped, "=", "\\=")
	return escaped
}

func deriveSeverity(rec SIEMRecord) int {
	if sev, ok := scoreToSeverity(rec.UserRiskData.Score); ok {
		return sev
	}
	if sev, ok := scoreToSeverity(rec.BotData.BotScore); ok {
		return sev
	}
	return 5
}

func eventNameFromAction(action string) string {
	switch strings.ToLower(action) {
	case "mitigate":
		return "Activity mitigated"
	case "deny":
		return "Activity denied"
	case "alert":
		return "Activity alerted"
	case "monitor":
		return "Activity monitored"
	default:
		return ""
	}
}

func firstFromSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func lastFromSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func scoreToSeverity(score string) (int, bool) {
	if score == "" {
		return 0, false
	}

	val, err := strconv.Atoi(score)
	if err != nil {
		return 0, false
	}

	if val < 0 {
		val = 0
	}
	if val > 100 {
		val = 100
	}

	return val / 10, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type cefHeader struct {
	DeviceVendor  string
	DeviceProduct string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      int
}

type cefBuilder struct {
	header     cefHeader
	extensions []string
}

func newCEFBuilder(header cefHeader) cefBuilder {
	return cefBuilder{header: header}
}

func (b *cefBuilder) add(key, value string) {
	if value == "" {
		return
	}
	b.extensions = append(b.extensions, fmt.Sprintf("%s=%s", key, escapeCEFValue(value)))
}

func (b *cefBuilder) addInt64(key string, value int64) {
	b.add(key, strconv.FormatInt(value, 10))
}

func (b *cefBuilder) addLabeled(labelKey, labelValue, key, value string) {
	if value == "" {
		return
	}
	if labelValue != "" {
		b.add(labelKey, labelValue)
	}
	b.add(key, value)
}

func (b *cefBuilder) String() string {
	header := fmt.Sprintf(
		"CEF:0|%s|%s|%s|%s|%s|%d|",
		escapeCEFValue(b.header.DeviceVendor),
		escapeCEFValue(b.header.DeviceProduct),
		escapeCEFValue(b.header.DeviceVersion),
		escapeCEFValue(b.header.SignatureID),
		escapeCEFValue(b.header.Name),
		b.header.Severity,
	)

	return header + strings.Join(b.extensions, " ")
}

func normalizedProtocol(protocol string) string {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return ""
	}
	return strings.ToLower(protocol)
}

func appendSourceExtensions(builder *cefBuilder, clientIP string) {
	if clientIP == "" {
		return
	}

	if strings.Contains(clientIP, ":") {
		builder.add("c6a2Label", "Source IPv6 Address")
		builder.add("c6a2", clientIP)
	}
	builder.add("src", clientIP)
}

func appendDestinationExtensions(builder *cefBuilder, msg HTTPMessage) {
	if msg.Host != "" {
		builder.add("dst", msg.Host)
		builder.add("dhost", msg.Host)
	}
	builder.add("dpt", msg.Port)
}

func appendRuleExtensions(builder *cefBuilder, rec SIEMRecord) {
	msg := strings.Join(rec.AttackData.RuleMessages, "; ")
	cs1 := strings.Join(rec.AttackData.Rules, ";")
	cs2 := msg
	cs3 := strings.Join(rec.AttackData.RuleData, "; ")
	cs4 := strings.Join(rec.AttackData.RuleSelectors, "; ")
	cs5 := rec.UserRiskData.Risk
	cs6 := rec.HTTPMessage.RequestID

	builder.add("msg", msg)
	builder.addLabeled("cs1Label", "Rules", "cs1", cs1)
	builder.addLabeled("cs2Label", "Rule Messages", "cs2", cs2)
	builder.addLabeled("cs3Label", "Rule Data", "cs3", cs3)
	builder.addLabeled("cs4Label", "Rule Selectors", "cs4", cs4)
	builder.addLabeled("cs5Label", "Client Reputation", "cs5", cs5)
	builder.addLabeled("cs6Label", "API ID", "cs6", cs6)
	builder.add("devicePayloadId", rec.HTTPMessage.RequestID)
	builder.addLabeled("flexString1Label", "Security Config Id", "flexString1", rec.AttackData.ConfigID)
	builder.addLabeled("flexString2Label", "Firewall Policy Id", "flexString2", rec.AttackData.PolicyID)
	builder.add("out", rec.HTTPMessage.Bytes)

	if len(rec.AttackData.RuleTags) > 0 {
		builder.add("AkamaiSiemRuleTags", strings.Join(rec.AttackData.RuleTags, "/"))
	}
}

func appendContextExtensions(builder *cefBuilder, rec SIEMRecord) {
	if len(rec.HTTPMessage.RequestHeaders) > 0 {
		builder.add("AkamaiSiemRequestHeaders", strings.Join(rec.HTTPMessage.RequestHeaders, "\n"))
	}
	if len(rec.HTTPMessage.ResponseHeaders) > 0 {
		builder.add("AkamaiSiemResponseHeaders", strings.Join(rec.HTTPMessage.ResponseHeaders, "\n"))
	}
	builder.add("AkamaiSiemResponseStatus", rec.HTTPMessage.Status)
	builder.add("AkamaiSiemContinent", rec.Geo.Continent)
	builder.add("AkamaiSiemCountry", rec.Geo.Country)
	builder.add("AkamaiSiemCity", rec.Geo.City)
	builder.add("AkamaiSiemRegion", rec.Geo.RegionCode)
	builder.add("AkamaiSiemASN", rec.Geo.ASN)
}

func newSocketConn(target string) (net.Conn, error) {
	if target == "" {
		return nil, nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	network := strings.ToLower(u.Scheme)
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported target scheme: %s", u.Scheme)
	}

	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("target missing host")
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "514")
	}

	return net.Dial(network, host)
}

type recordSink struct {
	format  string
	conn    net.Conn
	encoder *json.Encoder
}

func newRecordSink(format string, conn net.Conn) *recordSink {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	return &recordSink{
		format:  format,
		conn:    conn,
		encoder: enc,
	}
}

func (s *recordSink) EmitRecord(rec SIEMRecord) {
	if s.format == "cef" {
		cef := buildCEF(rec)
		if s.conn != nil {
			if _, err := fmt.Fprintf(s.conn, "%s\n", cef); err != nil {
				fmt.Fprintf(os.Stderr, "failed to send message: %v\n", err)
			}
			return
		}
		fmt.Fprintln(os.Stdout, cef)
		return
	}

	s.encoder.Encode(rec)
}

func (s *recordSink) EmitMetadata(mdt SIEMMetadata) {
	s.encoder.Encode(mdt)
}

func loadEdgeGridConfig(opts Options) (*edgegrid.Config, error) {
	egpath, err := homedir.Expand(opts.EdgeGridFile)
	if err != nil {
		return nil, err
	}

	var edgerc *edgegrid.Config
	if _, err := os.Stat(egpath); err == nil {
		edgerc, err = edgegrid.New(
			edgegrid.WithFile(egpath),
			edgegrid.WithSection(opts.EdgeGridSection),
		)
		if err != nil {
			return nil, err
		}
	} else {
		edgerc, _ = edgegrid.New()
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
	}

	if edgerc.Host == "" || edgerc.ClientToken == "" || edgerc.ClientSecret == "" || edgerc.AccessToken == "" {
		return nil, fmt.Errorf("failed to load edgegrid configuration")
	}

	return edgerc, nil
}

func getSIEMRecords(opts *Options, edgerc *edgegrid.Config, sink *recordSink) error {
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

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := scanner.Bytes()

		var rec SIEMRecord
		if err := json.Unmarshal(line, &rec); err == nil && rec.Type == "akamai_siem" {
			sink.EmitRecord(rec)
			continue
		}

		var mdt SIEMMetadata
		if err := json.Unmarshal(line, &mdt); err != nil {
			continue
		}

		opts.Offset = mdt.Offset
		sink.EmitMetadata(mdt)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func run() error {
	var opts Options
	if _, err := flags.Parse(&opts); err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	opts.normalize()
	if err := opts.validate(); err != nil {
		return err
	}

	conn, err := newSocketConn(opts.Syslog)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}

	sink := newRecordSink(opts.Format, conn)

	edgerc, err := loadEdgeGridConfig(opts)
	if err != nil {
		return err
	}

	if err := getSIEMRecords(&opts, edgerc, sink); err != nil {
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
			if err := getSIEMRecords(&opts, edgerc, sink); err != nil {
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
