package logfile

import (
	"strings"
	"testing"
	"time"

	"google3/third_party/golang/cmp/cmp"
)

func TestScanLogLines(t *testing.T) {
	scanTests := []struct {
		name    string
		data    string
		atEOF   bool
		advance int
		token   string
	}{
		{
			name: "empty log",
			data: "", atEOF: true,
			advance: 0, token: "",
		},
		{
			name: "trailing text",
			data: "foo", atEOF: true,
			advance: 3, token: "foo",
		},
		{
			name: "timestamp not at start of line",
			data: "fooI0825 15:31:48.798442  4 PPNLog.mm:9]", atEOF: true,
			advance: 40, token: "fooI0825 15:31:48.798442  4 PPNLog.mm:9]",
		},
		{
			name: "normal line",
			data: `
foo
I0825 15:31:48.798442  4 PPNLog.mm:9]`, atEOF: true,
			advance: 4, token: "foo\n",
		},
		{
			name: "two log lines",
			data: `
I0825 15:31:48.798442  4 PPNLog.mm:9] foo
I0825 15:31:48.798443  5 PPNLog.mm:9]`,
			atEOF:   true,
			advance: 42, token: "I0825 15:31:48.798442  4 PPNLog.mm:9] foo\n",
		},
		{
			name:    "log starting at second character of file",
			data:    "_I0825 15:31:48.798442  4 PPNLog.mm:9] foo",
			atEOF:   true,
			advance: 42, token: "_I0825 15:31:48.798442  4 PPNLog.mm:9] foo",
		},
	}

	for _, tt := range scanTests {
		t.Run(tt.name, func(t *testing.T) {
			advance, token, err := scanLogLines([]byte(strings.TrimSpace(tt.data)), tt.atEOF)
			if err != nil {
				t.Errorf("scanLogLines(%q, %v) = %v", tt.data, tt.atEOF, err)
				return
			}
			if advance != tt.advance || string(token) != tt.token {
				t.Errorf("scanLogLines(%q, %v) = (%d, %q); want (%d, %q)", tt.data, tt.atEOF, advance, token, tt.advance, tt.token)
			}
		})
	}
}

func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return tm
}

func TestScanner(t *testing.T) {
	scannerTests := []struct {
		name    string
		text    string
		entries []LogEntry
	}{
		{
			name: "basic case",
			text: `
I0102 03:04:05.000000006 7 a.c:8] foo
I0203 04:05:06.000000007 8 a.c:9] bar
I0304 05:06:07.000000008 9 a.c:10] baz`,
			entries: []LogEntry{
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-01-02T03:04:05.000000006Z"),
					Text:      "I0102 03:04:05.000000006 7 a.c:8] foo\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-02-03T04:05:06.000000007Z"),
					Text:      "I0203 04:05:06.000000007 8 a.c:9] bar\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-03-04T05:06:07.000000008Z"),
					Text:      "I0304 05:06:07.000000008 9 a.c:10] baz",
				},
			},
		},
		{
			name: "multi-line entry",
			text: `
I0102 03:04:05.000000006 7 a.c:8] foo
I0203 04:05:06.000000007 8 a.c:9] bar

  BAR  

bar
I0304 05:06:07.000000008 9 a.c:10] baz`,
			entries: []LogEntry{
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-01-02T03:04:05.000000006Z"),
					Text:      "I0102 03:04:05.000000006 7 a.c:8] foo\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-02-03T04:05:06.000000007Z"),
					Text: `I0203 04:05:06.000000007 8 a.c:9] bar

  BAR  

bar
`,
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-03-04T05:06:07.000000008Z"),
					Text:      "I0304 05:06:07.000000008 9 a.c:10] baz",
				},
			},
		},
		{
			name: "extra text at the beginning of the file",
			text: `
STUFF
I0102 03:04:05.000000006 7 a.c:8] foo
I0203 04:05:06.000000007 8 a.c:9] bar
I0304 05:06:07.000000008 9 a.c:10] baz`,
			entries: []LogEntry{
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-01-02T03:04:05.000000006Z"),
					Text:      "I0102 03:04:05.000000006 7 a.c:8] foo\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-02-03T04:05:06.000000007Z"),
					Text:      "I0203 04:05:06.000000007 8 a.c:9] bar\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-03-04T05:06:07.000000008Z"),
					Text:      "I0304 05:06:07.000000008 9 a.c:10] baz",
				},
			},
		},
		{
			name: "different precision of fractional time",
			text: `
I0102 03:04:05.006 7 a.c:8] foo
I0203 04:05:06.007 8 a.c:9] bar
I0304 05:06:07.008 9 a.c:10] baz`,
			entries: []LogEntry{
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-01-02T03:04:05.006000000Z"),
					Text:      "I0102 03:04:05.006 7 a.c:8] foo\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-02-03T04:05:06.007000000Z"),
					Text:      "I0203 04:05:06.007 8 a.c:9] bar\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-03-04T05:06:07.008000000Z"),
					Text:      "I0304 05:06:07.008 9 a.c:10] baz",
				},
			},
		},
		{
			name: "new year rollover",
			text: `
I1202 03:04:05.000000006 7 a.c:8] foo
I0203 04:05:06.000000007 8 a.c:9] bar`,
			entries: []LogEntry{
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2022-12-02T03:04:05.000000006Z"),
					Text:      "I1202 03:04:05.000000006 7 a.c:8] foo\n",
				},
				LogEntry{
					Timestamp: mustParseRFC3339(t, "2023-02-03T04:05:06.000000007Z"),
					Text:      "I0203 04:05:06.000000007 8 a.c:9] bar",
				},
			},
		},
	}

	for _, tt := range scannerTests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner(strings.NewReader(strings.TrimSpace(tt.text)), 2022)
			for _, wantEntry := range tt.entries {
				gotEntry := s.Next()
				if gotEntry == nil || !cmp.Equal(*gotEntry, wantEntry) {
					t.Errorf("s.Next() = %v; want %v", gotEntry, wantEntry)
				}
			}
			gotEntry := s.Next()
			if gotEntry != nil {
				t.Errorf("s.Next() = %v; want %v", gotEntry, nil)
			}
		})
	}
}
