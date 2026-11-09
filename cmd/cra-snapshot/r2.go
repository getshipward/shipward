package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// runName matches the run folders the builder writes, so nothing else in the bucket is ever deleted.
var runName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

type r2Config struct {
	Endpoint, Bucket, KeyID, Secret string
}

// enabled reports whether all R2 settings are given; some but not all is an error.
func (c r2Config) enabled() (bool, error) {
	set := 0
	for _, v := range []string{c.Endpoint, c.Bucket, c.KeyID, c.Secret} {
		if v != "" {
			set++
		}
	}
	switch set {
	case 0:
		return false, nil
	case 4:
		return true, nil
	}
	return false, errors.New("set all of R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY, or none")
}

// publish uploads the run's data files, then index.json, below prefix (the format folder, "v1/"), then deletes run
// folders beyond the newest keep. Data files never change once written (a new run gets a new folder), so they may be
// cached for a year; the index for 5 minutes.
func (c r2Config) publish(ctx context.Context, log *slog.Logger, dir string, files []string, prefix string, keep int) error {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" {
		return errors.New("R2_ENDPOINT must be a URL such as https://<account>.eu.r2.cloudflarestorage.com")
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(c.KeyID, c.Secret, ""),
		Secure: u.Scheme == "https",
		Region: "auto",
	})
	if err != nil {
		return err
	}

	for _, rel := range files {
		opts := minio.PutObjectOptions{ContentType: "application/gzip", CacheControl: "public, max-age=31536000, immutable"}
		if rel == "index.json" {
			opts = minio.PutObjectOptions{ContentType: "application/json", CacheControl: "public, max-age=300"}
		}
		if _, err := client.FPutObject(ctx, c.Bucket, prefix+rel, filepath.Join(dir, filepath.FromSlash(rel)), opts); err != nil {
			return fmt.Errorf("upload %s: %w", rel, err)
		}
	}
	log.Info("published", "bucket", c.Bucket, "files", len(files))

	// Run folders are named by time (20061102T150405Z), so they sort by age.
	var runs []string
	for obj := range client.ListObjects(ctx, c.Bucket, minio.ListObjectsOptions{Prefix: prefix}) {
		if obj.Err != nil {
			return obj.Err
		}
		if run, ok := strings.CutSuffix(strings.TrimPrefix(obj.Key, prefix), "/"); ok && runName.MatchString(run) {
			runs = append(runs, run)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(runs)))
	keep = max(keep, 1) // never the run just published
	if len(runs) <= keep {
		return nil
	}
	for _, run := range runs[keep:] {
		for obj := range client.ListObjects(ctx, c.Bucket, minio.ListObjectsOptions{Prefix: prefix + run + "/", Recursive: true}) {
			if obj.Err != nil {
				return obj.Err
			}
			if err := client.RemoveObject(ctx, c.Bucket, obj.Key, minio.RemoveObjectOptions{}); err != nil {
				return err
			}
		}
		log.Info("removed old run", "run", run)
	}
	return nil
}
