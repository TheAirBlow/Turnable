package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/version"
)

const (
	repoSlug      = "TheAirBlow/Turnable"
	updateTmpGlob = ".turnable-update-*"
	oldSuffix     = ".old"
)

var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// updateOptions holds CLI flags for the update subcommand
type updateOptions struct {
	force bool // update even on dev builds or when already up to date
	clean bool // remove leftover update files and exit
}

// newUpdateCommand creates the update cobra command
func newUpdateCommand() *cobra.Command {
	opts := &updateOptions{}

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update to the latest release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateMain(opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "update even on dev builds or when already up to date")
	cmd.Flags().BoolVarP(&opts.clean, "clean", "c", false, "remove leftover update files and exit")

	return cmd
}

// updateMain runs the update command
func updateMain(opts *updateOptions) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate own executable: %w", err)
	}
	if exePath, err = filepath.EvalSymlinks(exePath); err != nil {
		return fmt.Errorf("failed to resolve own executable: %w", err)
	}

	if opts.clean {
		return cleanUpdateFiles(exePath)
	}

	tmp, err := createUpdateTemp(exePath)
	if err != nil {
		return fmt.Errorf("cannot replace %s: %w", exePath, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()

	current := version.String()
	if !releaseVersion.MatchString(current) && !opts.force {
		return fmt.Errorf("this is a dev build (%s), use --force to update anyway", current)
	}

	latest, err := fetchLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	if latest == current && !opts.force {
		slog.Info("already up to date", "version", current)
		return nil
	}

	asset := assetName()
	slog.Info("downloading update", "from", current, "to", latest, "asset", asset)
	if err := download(fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repoSlug, latest, asset), tmp); err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := replaceExecutable(exePath, tmpPath); err != nil {
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	slog.Info("successfully updated", "version", latest)
	return nil
}

// createUpdateTemp creates a temp file next to the executable, which also proves it can be replaced
func createUpdateTemp(exePath string) (*os.File, error) {
	return os.CreateTemp(filepath.Dir(exePath), updateTmpGlob)
}

// assetName returns the release asset name for this platform
func assetName() string {
	name := fmt.Sprintf("turnable-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// fetchLatestVersion returns the tag of the latest GitHub release
func fetchLatestVersion() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + repoSlug + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", errors.New("latest release has no tag")
	}

	return release.TagName, nil
}

// download writes the response body of url to dst
func download(url string, dst io.Writer) error {
	client := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	n, err := io.Copy(dst, resp.Body)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("downloaded file is empty")
	}

	return nil
}

// replaceExecutable swaps newPath in for exePath, keeping its permissions
func replaceExecutable(exePath, newPath string) error {
	info, err := os.Stat(exePath)
	if err != nil {
		return err
	}
	if err := os.Chmod(newPath, info.Mode().Perm()); err != nil {
		return err
	}

	if runtime.GOOS != "windows" {
		return os.Rename(newPath, exePath)
	}

	// a running exe can be renamed but not overwritten, the old copy is removed by --clean
	oldPath := exePath + oldSuffix
	_ = os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		return err
	}
	if err := os.Rename(newPath, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		return err
	}

	return nil
}

// cleanUpdateFiles removes temp files and the old executable left behind by earlier updates
func cleanUpdateFiles(exePath string) error {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(exePath), updateTmpGlob))
	if err != nil {
		return err
	}
	matches = append(matches, exePath+oldSuffix)

	removed := 0
	for _, path := range matches {
		if err := os.Remove(path); err == nil {
			removed++
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}

	slog.Info("cleaned up update files", "removed", removed)
	return nil
}
