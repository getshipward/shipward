package snapshot

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fetcher downloads the public feeds. It sends plain GET requests and nothing about the product.
type Fetcher struct {
	HTTP      *http.Client
	UserAgent string
}

// euvdPageSize is the most records EUVD's search returns per request.
const euvdPageSize = 100

// KEV reads CISA's Known Exploited Vulnerabilities catalog (CC0 1.0).
func (f *Fetcher) KEV(ctx context.Context, url string) (map[string]KEV, error) {
	var kev struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Added      string `json:"dateAdded"`
			Due        string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := f.getJSON(ctx, url, &kev); err != nil {
		return nil, err
	}
	out := make(map[string]KEV, len(kev.Vulnerabilities))
	for _, v := range kev.Vulnerabilities {
		if ValidCVE(v.CVE) {
			out[v.CVE] = KEV{Added: v.Added, Due: v.Due, Ransomware: v.Ransomware}
		}
	}
	// The catalog has well over a thousand entries: an empty answer is a broken one, not an empty list.
	if len(out) == 0 {
		return nil, errors.New("the KEV catalog has no entries")
	}
	return out, nil
}

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ValidCVE reports whether s is a CVE ID (CVE-YYYY-NNNN, four or more digits).
func ValidCVE(s string) bool { return cveID.MatchString(s) }

// UsableEUVD returns the entries of an ENISA list that can mark an advisory: a non-blank key and a non-blank EUVD ID.
func UsableEUVD(m map[string]EUVD) map[string]EUVD {
	out := make(map[string]EUVD, len(m))
	for k, e := range m {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(e.ID) != "" {
			out[k] = e
		}
	}
	return out
}

// EUVD reads ENISA's exploited vulnerabilities, keyed by every ID ENISA lists for an entry: its own EUVD ID and its
// aliases (CVE, GHSA and others), so an advisory without a CVE alias still matches.
func (f *Fetcher) EUVD(ctx context.Context, url string) (map[string]EUVD, error) {
	out := map[string]EUVD{}
	for page := 0; ; page++ {
		var res struct {
			Total int `json:"total"`
			Items []struct {
				ID             string `json:"id"`
				Aliases        string `json:"aliases"`
				ExploitedSince string `json:"exploitedSince"`
			} `json:"items"`
		}
		u := fmt.Sprintf("%s?exploited=true&size=%d&page=%d", url, euvdPageSize, page)
		if err := f.getJSON(ctx, u, &res); err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		for _, it := range res.Items {
			it.ID = strings.TrimSpace(it.ID)
			if it.ID == "" {
				continue
			}
			e := EUVD{ID: it.ID, ExploitedSince: euvdDate(it.ExploitedSince)}
			for _, id := range append([]string{it.ID}, strings.Fields(it.Aliases)...) {
				out[id] = e
			}
		}
		if len(res.Items) < euvdPageSize || (page+1)*euvdPageSize >= res.Total {
			// ENISA lists hundreds of exploited vulnerabilities: an empty answer is a broken one, not an empty list.
			if len(out) == 0 {
				return nil, errors.New("ENISA's list of exploited vulnerabilities has no entries")
			}
			return out, nil
		}
		if page >= 1000 {
			return nil, errors.New("more than 1000 pages")
		}
	}
}

// euvdDate turns EUVD's "Nov 4, 2026, 12:00:00 AM" into 2026-11-04 (or keeps the text when it does not parse).
func euvdDate(s string) string {
	t, err := time.Parse("Jan 2, 2006, 3:04:05 PM", s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02")
}

// ParseEPSS reads FIRST's daily EPSS CSV (gzip) and keeps the CVEs keep accepts. The first line is a comment with the
// model version and score date, which it returns.
func ParseEPSS(r io.Reader, keep func(cve string) bool) (map[string]EPSS, string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, "", err
	}
	br := bufio.NewReader(gz)
	date := ""
	if first, err := br.Peek(1); err == nil && first[0] == '#' {
		line, _ := br.ReadString('\n')
		for _, part := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "#")), ",") {
			if v, ok := strings.CutPrefix(part, "score_date:"); ok {
				date = v
			}
		}
	}
	cr := csv.NewReader(br)
	if _, err := cr.Read(); err != nil { // header: cve,epss,percentile
		return nil, "", err
	}
	out := map[string]EPSS{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, date, nil
		}
		if err != nil {
			return nil, "", err
		}
		if len(rec) < 3 || !keep(rec[0]) {
			continue
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 == nil && err2 == nil {
			out[rec[0]] = EPSS{Score: score, Percentile: pct}
		}
	}
}

func (f *Fetcher) request(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	return req, nil
}

func (f *Fetcher) download(ctx context.Context, u string, w io.Writer) error {
	req, err := f.request(ctx, u)
	if err != nil {
		return err
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (f *Fetcher) getJSON(ctx context.Context, u string, v any) error {
	req, err := f.request(ctx, u)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
