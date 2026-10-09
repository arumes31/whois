package handler

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"whois/internal/model"
	"whois/internal/utils"

	"github.com/labstack/echo/v5"
)

func (h *Handler) DNSLookup(c *echo.Context) error {
	domain := strings.TrimSpace(c.FormValue("domain"))
	recordType := strings.ToUpper(strings.TrimSpace(c.FormValue("type")))
	if recordType == "" {
		recordType = "A"
	}
	target := utils.NormalizeTarget(domain)
	if !target.Valid || !target.Networkable {
		return c.HTML(http.StatusBadRequest, `<div class="alert-err">Error: invalid DNS target</div>`)
	}
	isIP := target.Kind == model.TargetKindIPv4 || target.Kind == model.TargetKindIPv6
	detail, lookupErr := h.DNS.LookupTypeDetailed(c.Request().Context(), target.Host, recordType, isIP)
	status := http.StatusOK
	if lookupErr != nil && detail.Resolver == "" {
		// Preserve invalid-input responses. Once a resolver has been queried,
		// failure is a diagnostic outcome whose evidence the tool can display.
		status = http.StatusBadRequest
	}
	markup, err := renderDNSLookup(detail)
	if err != nil {
		return err
	}
	return c.HTML(status, markup)
}

func renderDNSLookup(detail model.DNSQueryDetail) (string, error) {
	view := struct {
		Detail       model.DNSQueryDetail
		Outcome      string
		Summary      string
		Observed     string
		Transport    string
		Negative     bool
		DNSSECRecord bool
	}{
		Detail: detail, Transport: strings.ToUpper(detail.Transport),
		DNSSECRecord: detail.QueryType == "DS" || detail.QueryType == "DNSKEY",
	}
	switch detail.Status {
	case "answer":
		view.Outcome = "ANSWER"
	case "nxdomain":
		view.Outcome, view.Negative = "NXDOMAIN", true
		if len(detail.Aliases) > 0 || detail.QueryType == "CNAME" && len(detail.Records) > 0 {
			view.Summary = "The alias target does not exist."
		} else {
			view.Summary = "The queried name does not exist."
		}
	case "nodata":
		view.Outcome, view.Negative = "NODATA", true
		view.Summary = fmt.Sprintf("No %s records found for %s", detail.QueryType, detail.QueryName)
	default:
		view.Outcome = "LOOKUP FAILED"
	}
	if !detail.ObservedAt.IsZero() {
		view.Observed = detail.ObservedAt.UTC().Format(time.RFC3339)
	}
	var output bytes.Buffer
	if err := dnsLookupTemplate.Execute(&output, view); err != nil {
		return "", err
	}
	return output.String(), nil
}

var dnsLookupTemplate = template.Must(template.New("dns-lookup").Parse(`
<div class="dns-type">{{.Detail.QueryType}} RECORDS FOR {{.Detail.QueryName}}</div>
<div class="{{if eq .Detail.Status "error"}}alert-err{{else if eq .Detail.Status "answer"}}alert-ok{{else}}result-note{{end}}"><strong>{{.Outcome}}</strong>{{if .Summary}} — {{.Summary}}{{end}}</div>
<dl class="kv"><dt>Query</dt><dd>{{.Detail.QueryName}} · {{.Detail.QueryType}}</dd></dl>
{{if .Detail.Rcode}}<dl class="kv"><dt>Response code</dt><dd>{{.Detail.Rcode}}</dd></dl>{{end}}
{{if .Detail.Resolver}}<dl class="kv"><dt>Resolver</dt><dd>{{.Detail.Resolver}}{{if .Transport}} ({{.Transport}}){{end}}</dd></dl>{{end}}
{{if .Observed}}<dl class="kv"><dt>Observed</dt><dd>{{.Observed}}</dd></dl>{{end}}
{{if .Negative}}<dl class="kv"><dt>Negative-cache TTL</dt><dd>{{if .Detail.NegativeTTL}}{{.Detail.NegativeTTL}} s at observation{{else}}not provided{{end}}</dd></dl>{{end}}
{{if .Detail.Error}}<p class="alert-err">{{.Detail.Error}}</p>{{end}}
{{range .Detail.Aliases}}<p class="result-note">CNAME {{.Name}} → <span class="clickable-record">{{.Value}}</span> · TTL {{.TTL}} s</p>{{end}}
{{if .Detail.Records}}<div class="dns-values">{{range .Detail.Records}}
<div class="dns-record"><span class="clickable-record">{{.Value}}</span></div>
<p class="result-note">{{.Name}} · TTL {{.TTL}} s</p>
{{end}}</div>{{end}}
<p class="result-note">TTL values are seconds remaining when observed.{{if .DNSSECRecord}} DNSSEC signatures have not been validated by this application.{{end}}</p>
`))
