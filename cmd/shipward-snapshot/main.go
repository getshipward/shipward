// Command shipward-snapshot builds the daily vulnerability snapshot (internal/snapshot) and, with R2 settings,
// publishes it. It runs once a day. It reads only public data and sends nothing but plain downloads to the sources.
//
//	SNAPSHOT_SIGNING_KEY=<base64 seed> shipward-snapshot -out ./snap            # build only
//	SNAPSHOT_SIGNING_KEY=... R2_ENDPOINT=... R2_BUCKET=... R2_ACCESS_KEY_ID=... R2_SECRET_ACCESS_KEY=... shipward-snapshot
//	shipward-snapshot -new-key                                                  # print a new key pair
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getshipward/shipward/internal/snapshot"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("snapshot failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	out := flag.String("out", "", "build folder (default: a temporary folder, removed after the upload)")
	ecosystems := flag.String("ecosystems", strings.Join(snapshot.DefaultEcosystems, ","), "OSV ecosystems, comma-separated")
	keep := flag.Int("keep", 3, "run folders to keep in the bucket (older ones are deleted)")
	newKey := flag.Bool("new-key", false, "print a new signing key (seed) and its public key, then exit")
	flag.Parse()

	if *newKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Printf("SNAPSHOT_SIGNING_KEY=%s\npublic key (internal/snapshot TrustedKeys): %s\n",
			base64.StdEncoding.EncodeToString(priv.Seed()), snapshot.PublicKey(priv))
		return nil
	}

	key, err := snapshot.ParseKey(os.Getenv("SNAPSHOT_SIGNING_KEY"))
	if err != nil {
		return err
	}
	r2 := r2Config{
		Endpoint: os.Getenv("R2_ENDPOINT"),
		Bucket:   os.Getenv("R2_BUCKET"),
		KeyID:    os.Getenv("R2_ACCESS_KEY_ID"),
		Secret:   os.Getenv("R2_SECRET_ACCESS_KEY"),
	}
	upload, err := r2.enabled()
	if err != nil {
		return err
	}
	if !upload && *out == "" {
		return errors.New("give -out, or the R2 settings to publish")
	}

	dir := *out
	if dir == "" {
		dir, err = os.MkdirTemp("", "snapshot-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b := &snapshot.Builder{
		HTTP:        &http.Client{Timeout: 10 * time.Minute},
		Ecosystems:  strings.Split(*ecosystems, ","),
		Records:     recordSources,
		FeedSources: feedSources,
		OSVBase:     snapshot.OSVBase,
		KEVURLs:     []string{snapshot.KEVURL, snapshot.KEVMirrorURL},
		UserAgent:   "shipward-snapshot/" + version + " (+https://shipward.dev)",
		Log:         log,
		Now:         time.Now,
	}
	files, err := b.Build(ctx, dir, key)
	if err != nil {
		return err
	}
	log.Info("built", "dir", dir, "files", len(files))
	if !upload {
		return nil
	}
	return r2.publish(ctx, log, dir, files, fmt.Sprintf("v%d/", snapshot.Format), *keep)
}
