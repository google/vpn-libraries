// logtool is a simple script for taking the logs zip file from the Google One
// app for Windows and extracting the various individual files, concatenating
// them, and merging their log lines.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"time"

	"google3/base/go/flag"
	"google3/base/go/google"
	"google3/base/go/log"
	"google3/privacy/net/krypton/desktop/windows/logtool/logfile"
	"google3/security/safearchive/zip"
)

const (
	timeFormat = "20060102_150405.999999999"
)

var (
	zipFile = flag.String("zip_file", "", "Path to the Windows VPN logs zip file.")
	outFile = flag.String("output_file", "", "Path to output merged log text file.")

	// Each filename is formatted like $PREFIX_20221026_162315.576032213.txt
	fileNamePattern = regexp.MustCompile(`^.*_(\d{8}_\d{6}\.[0-9]+)\.txt$`)
)

func parseFileTime(file string) (time.Time, error) {
	matches := fileNamePattern.FindStringSubmatch(file)
	if matches == nil {
		return time.Time{}, fmt.Errorf("file does not match expected pattern: %q", file)
	}

	return time.Parse(timeFormat, matches[1])
}

type logFile struct {
	file *zip.File
	time time.Time
}

type byTime []logFile

func (a byTime) Len() int {
	return len(a)
}

func (a byTime) Less(i, j int) bool {
	return a[i].time.Before(a[j].time)
}

func (a byTime) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Merges the logs from a single directory in the zip into the given writer.
func mergeDir(files []*zip.File, dir string, w io.Writer) (start time.Time, err error) {
	log.Infof("Merging files in directory %q.", dir)

	sorted := byTime{}

	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		if path.Dir(f.Name) != dir {
			continue
		}

		tm, err := parseFileTime(f.Name)
		if err != nil {
			return time.Time{}, fmt.Errorf("unable to parse time in name of %q: %v", f.Name, err)
		}

		sorted = append(sorted, logFile{
			file: f,
			time: tm,
		})
	}

	sort.Sort(sorted)

	for _, f := range sorted {
		log.Infof("Processing %q", f.file.Name)

		// Each log file is 5 KB, so it's safe to read the whole thing in memory.
		r, err := f.file.Open()
		if err != nil {
			return time.Time{}, fmt.Errorf("unable to open %q: %v", f.file.Name, err)
		}
		defer r.Close()
		if _, err := io.Copy(w, r); err != nil {
			return time.Time{}, fmt.Errorf("unable to copy %q: %v", f.file.Name, err)
		}
	}

	return sorted[0].time, nil
}

// Merges the logs from a single directory in the zip into a single temp file.
func mergeDirToTempFile(files []*zip.File, dir string) (path string, start time.Time, err error) {
	tmp, err := os.CreateTemp("", "logtool_*.txt")
	if err != nil {
		return "", time.Time{}, fmt.Errorf("unable to create temp file: %v", err)
	}
	defer tmp.Close()

	log.Infof("Writing %q logs to %q", dir, tmp.Name())
	start, err = mergeDir(files, dir, tmp)
	if err != nil {
		return "", time.Time{}, err
	}

	return tmp.Name(), start, nil
}

func processZip(zipFile string, outFile string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)

	appPath, appStart, err := mergeDirToTempFile(r.File, "app")
	if err != nil {
		return err
	}

	kryptonPath, kryptonStart, err := mergeDirToTempFile(r.File, "krypton_service")
	if err != nil {
		return err
	}

	// Merge the two temp files together.
	appFile, err := os.Open(appPath)
	if err != nil {
		return err
	}
	defer appFile.Close()
	appScanner := logfile.NewScanner(appFile, appStart.Year())

	kryptonFile, err := os.Open(kryptonPath)
	if err != nil {
		return err
	}
	defer kryptonFile.Close()
	kryptonScanner := logfile.NewScanner(kryptonFile, kryptonStart.Year())

	appEntry := appScanner.Next()
	kryptonEntry := kryptonScanner.Next()
	for appEntry != nil && kryptonEntry != nil {
		if appEntry.Timestamp.Before(kryptonEntry.Timestamp) {
			w.WriteString(appEntry.Text)
			appEntry = appScanner.Next()
		} else {
			w.WriteString(kryptonEntry.Text)
			kryptonEntry = kryptonScanner.Next()
		}
	}
	for appEntry != nil {
		w.WriteString(appEntry.Text)
		appEntry = appScanner.Next()
	}
	for kryptonEntry != nil {
		w.WriteString(kryptonEntry.Text)
		kryptonEntry = kryptonScanner.Next()
	}

	return nil
}

func main() {
	google.Init()

	if *zipFile == "" || *outFile == "" {
		log.Fatal("usage: logtool --zip_file=/path/to/file.zip --output_file=/path/to/file.txt")
	}

	if err := processZip(*zipFile, *outFile); err != nil {
		log.Fatalf("unable to process zip file: %s", err)
	}
}
