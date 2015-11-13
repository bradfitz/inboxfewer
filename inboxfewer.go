// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file:
// https://golang.org/LICENSE

// Inboxfewer archives messages in your gmail inbox if the
// corresponding github issue has been closed or the gerrit code
// review has been merged or abandoned.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/build/gerrit"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmail "google.golang.org/api/gmail/v1"
)

var githubUser, githubToken string

type FewerClient struct {
	svc *gmail.UsersService
}

func (c *FewerClient) ArchiveThread(tid string) error {
	_, err := c.svc.Threads.Modify("me", tid, &gmail.ModifyThreadRequest{
		RemoveLabelIds: []string{"INBOX"},
	}).Do()
	return err
}

func (c *FewerClient) ForeachThread(q string, fn func(*gmail.Thread) error) error {
	pageToken := ""
	for {
		req := c.svc.Threads.List("me").Q(q)
		if pageToken != "" {
			req.PageToken(pageToken)
		}
		res, err := req.Do()
		if err != nil {
			return err
		}
		for _, t := range res.Threads {
			if err := fn(t); err != nil {
				return err
			}
		}
		if res.NextPageToken == "" {
			return nil
		}
		pageToken = res.NextPageToken
	}
}

func readGithubConfig() {
	file := filepath.Join(os.Getenv("HOME"), "keys", "github-inboxfewer.token")
	slurp, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	f := strings.Fields(strings.TrimSpace(string(slurp)))
	if len(f) != 2 {
		log.Fatalf("expected two fields (user and token) in %v; got %d fields", file, len(f))
	}
	githubUser, githubToken = f[0], f[1]
}

// PopulateThread populates t with its full data. t.Id must be set initially.
func (c *FewerClient) PopulateThread(t *gmail.Thread) error {
	req := c.svc.Threads.Get("me", t.Id).Format("full")
	tfull, err := req.Do()
	if err != nil {
		return err
	}
	*t = *tfull
	return nil
}

func main() {
	const OOB = "urn:ietf:wg:oauth:2.0:oob"
	conf := &oauth2.Config{
		ClientID: "881077086782-039l7vctubc7vrvjmubv6a7v0eg96sqg.apps.googleusercontent.com", // proj: inbox-fewer

		// https://developers.google.com/identity/protocols/OAuth2InstalledApp
		// says: "The client ID and client secret obtained
		// from the Developers Console are embedded in the
		// source code of your application. In this context,
		// the client secret is obviously not treated as a
		// secret."
		ClientSecret: "y9Rj5-KheyZSFyjCH1dCBXWs",

		Endpoint:    google.Endpoint,
		RedirectURL: OOB,
		Scopes:      []string{gmail.MailGoogleComScope},
	}

	cacheDir := filepath.Join(userCacheDir(), "inboxfewer")
	gmailTokenFile := filepath.Join(cacheDir, "gmail.token")

	slurp, err := ioutil.ReadFile(gmailTokenFile)
	var ts oauth2.TokenSource
	if err == nil {
		f := strings.Fields(strings.TrimSpace(string(slurp)))
		if len(f) == 2 {
			ts = conf.TokenSource(context.Background(), &oauth2.Token{
				AccessToken:  f[0],
				TokenType:    "Bearer",
				RefreshToken: f[1],
				Expiry:       time.Unix(1, 0),
			})
			if _, err := ts.Token(); err != nil {
				log.Printf("Cached token invalid: %v", err)
				ts = nil
			}
		}
	}

	if ts == nil {
		authCode := conf.AuthCodeURL("state")
		log.Printf("Go to %v", authCode)
		io.WriteString(os.Stdout, "Enter code> ")

		bs := bufio.NewScanner(os.Stdin)
		if !bs.Scan() {
			os.Exit(1)
		}
		code := strings.TrimSpace(bs.Text())
		t, err := conf.Exchange(context.Background(), code)
		if err != nil {
			log.Fatal(err)
		}
		os.MkdirAll(cacheDir, 0700)
		ioutil.WriteFile(gmailTokenFile, []byte(t.AccessToken+" "+t.RefreshToken), 0600)
		ts = conf.TokenSource(context.Background(), t)
	}

	client := oauth2.NewClient(context.Background(), ts)
	svc, err := gmail.New(client)
	if err != nil {
		log.Fatal(err)
	}

	readGithubConfig()

	fc := &FewerClient{
		svc: svc.Users,
	}
	n := 0
	if err := fc.ForeachThread("in:inbox", func(t *gmail.Thread) error {
		if err := fc.PopulateThread(t); err != nil {
			return err
		}
		topic := fc.ClassifyThread(t)
		n++
		log.Printf("Thread %d (%v) = %T %v", n, t.Id, topic, topic)
		if topic == nil {
			return nil
		}
		if stale, err := topic.IsStale(); err != nil {
			return err
		} else if stale {
			log.Printf("  ... archiving")
			return fc.ArchiveThread(t.Id)
		}
		return nil
	}); err != nil {
		log.Fatal(err)
	}
}

type message struct {
	size    int64
	gmailID string
	date    string // retrieved from message header
	snippet string
}

type threadType interface {
	IsStale() (bool, error)
}

type gerritChange struct {
	ID     string // "Innnnn"
	Server string // "go-review.googlesource.com"
}

func (gc gerritChange) IsStale() (bool, error) {
	c := gerrit.NewClient("https://"+gc.Server, gerrit.NoAuth)
	ci, err := c.GetChangeDetail(gc.ID)
	if err != nil {
		return false, err
	}
	switch ci.Status {
	case "SUBMITTED", "MERGED", "ABANDONED":
		return true, nil
	}
	return false, nil
}

type githubIssue struct {
	repo string // "golang/go"
	n    string // "123"
}

func (id githubIssue) IsStale() (bool, error) {
	issueURL := "https://api.github.com/repos/" + id.repo + "/issues/" + id.n
	req, _ := http.NewRequest("GET", issueURL, nil)
	req.SetBasicAuth(githubUser, githubToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, nil
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return true, nil
	}
	if res.StatusCode != 200 {
		return false, fmt.Errorf("fetching %v, http status %s", issueURL, res.Status)
	}
	var issue struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(res.Body).Decode(&issue); err != nil {
		return false, err
	}
	return issue.State == "closed", nil
}

var githubIssueID = regexp.MustCompile(`^<([\w-]+/[\w-]+)/issues/(\d+).*@github\.com>$`)

func (c *FewerClient) ClassifyThread(t *gmail.Thread) threadType {
	for _, m := range t.Messages {
		mpart := m.Payload
		if mpart == nil {
			continue
		}
		for _, mph := range mpart.Headers {
			if mph.Name == "X-Gerrit-Change-Id" {
				v := headerValue(m, "X-Gerrit-ChangeURL") // "<https://go-review.googlesource.com/12665>"
				v = strings.TrimPrefix(v, "<https://")
				v = v[:strings.LastIndex(v, "/")]
				return gerritChange{
					ID:     mph.Value,
					Server: v,
				}
			}
			// <golang/go/issues/3665/100642466@github.com>
			if mph.Name == "Message-ID" &&
				strings.Contains(mph.Value, "/issues/") &&
				strings.Contains(mph.Value, "@github.com>") {
				m := githubIssueID.FindStringSubmatch(mph.Value)
				if m != nil {
					return githubIssue{repo: m[1], n: m[2]}
				}
			}
		}
	}
	return nil
}

func headerValue(m *gmail.Message, header string) string {
	mpart := m.Payload
	if mpart == nil {
		return ""
	}
	for _, mph := range mpart.Headers {
		if mph.Name == header {
			return mph.Value
		}
	}
	return ""
}

func userCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(HomeDir(), "Library", "Caches")
	case "windows":
		// TODO: use Application Data instead, or something?

		// Per http://technet.microsoft.com/en-us/library/cc749104(v=ws.10).aspx
		// these should both exist. But that page overwhelms me. Just try them
		// both. This seems to work.
		for _, ev := range []string{"TEMP", "TMP"} {
			if v := os.Getenv(ev); v != "" {
				return ev
			}
		}
		panic("No Windows TEMP or TMP environment variables found")
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return xdg
	}
	return filepath.Join(HomeDir(), ".cache")
}

func HomeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return os.Getenv("HOME")
}
