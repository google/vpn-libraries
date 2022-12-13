// Package logfile provides utilities for processing a single log file.
package logfile

import (
	"bufio"
	"io"
	"regexp"
	"time"

	"google3/base/go/log"
)

var (
	// I0825 15:31:48.798442       4 PPNLog.mm:9]
	logLineRegexp = regexp.MustCompile(`(?m)^.(\d{4} \d\d:\d\d:\d\d\.\d*) *\d+ [^:]*:\d*\]`)
)

// LogEntry represents a single entry in a log file. May be multiple "lines".
type LogEntry struct {
	Timestamp time.Time
	Text      string
}

// bufio.SplitFunc implementation used by Scanner to separate log entries.
// A log entry can be multiple lines of text. Records are delimited by the
// regexp for the timestamp at the beginning of the line.
func scanLogLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) == 0 {
		return 0, nil, nil
	}

	// Search for the beginning of the next log line.
	locs := logLineRegexp.FindAllIndex(data, 2)
	index := 0
	if locs != nil {
		// If the first match was the beginning of the string, then it matched the
		// current record, so skip to the next one.
		if locs[0][0] == 0 && len(locs) > 1 {
			index = locs[1][0]
		} else {
			index = locs[0][0]
		}
	}

	if index == 0 {
		// No new log line was found.
		if atEOF {
			// Return everything that's left.
			return len(data), data, nil
		}
		// Request more data in the buffer.
		return 0, nil, nil
	}

	return index, data[0:index], nil
}

// Scanner is an iterator for reading log entries from a text log file.
type Scanner struct {
	scanner      *bufio.Scanner
	year         int
	previousTime time.Time
}

// NewScanner returns a new Scanner for reading LogEntry records from a file.
// The given year is used as the start of the file, since log lines have dates
// without years. The year will be incremented automatically if the dates roll
// over to an earlier day. The returned iterator has similar semantics to
// recordio.Reader. Malformed records are skipped.
func NewScanner(r io.Reader, year int) *Scanner {
	s := bufio.NewScanner(r)
	s.Split(scanLogLines)
	return &Scanner{
		scanner:      s,
		year:         year,
		previousTime: time.Time{},
	}
}

// Next returns the next LogEntry in the file. Returns nil at the end of file.
func (s *Scanner) Next() *LogEntry {
	// To skip malformed records, loop until a valid record can be returned.
	for {
		if !s.scanner.Scan() {
			if s.scanner.Err() != nil {
				log.Warningf("unable to scan logs: %v", s.scanner.Err())
			}
			// No more records will be able to be read.
			return nil
		}

		line := s.scanner.Text()

		matches := logLineRegexp.FindStringSubmatch(line)
		if matches == nil {
			log.Warningf("malformed line: %q", line)
			continue
		}

		tm, err := time.Parse("0102 15:04:05.999999999", matches[1])
		if err != nil {
			log.Warningf("malformed timestamp: %v", err)
			continue
		}
		tm = tm.AddDate(s.year, 0, 0)
		if s.previousTime.After(tm) {
			tm = tm.AddDate(1, 0, 0)
			s.year++
		}

		s.previousTime = tm
		return &LogEntry{
			Timestamp: tm,
			Text:      line,
		}
	}
}
