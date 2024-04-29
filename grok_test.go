package grok_test

import (
	"fmt"
	"testing"

	"github.com/elastic/grok-go"
	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	testCases := []struct {
		Name          string
		Patterns      map[string]string
		Pattern       string
		Text          string
		ExpectedMatch bool
	}{
		{"no pattern, no text", nil, ``, ``, true},
		{"no pattern, some text", nil, ``, `some text`, true},
		{"regex match", nil, `foo.*`, `seafood`, true},
		{"regex no match", nil, `bar.*`, `seafood`, false},

		// test from golang regex library
		{"Go regex 1", nil, `a+`, "baaab", true},
		{"Go regex 2", nil, "abcd..", "abcdef", true},
		{"Go regex 3", nil, `a`, "a", true},
		{"Go regex 4", nil, `x`, "y", false},
		{"Go regex 5", nil, `b`, "abc", true},
		{"Go regex 6", nil, `.`, "a", true},
		{"Go regex 7", nil, `.*`, "abcdef", true},
		{"Go regex 8", nil, `^`, "abcde", true},
		{"Go regex 9", nil, `$`, "abcde", true},
		{"Go regex 10", nil, `^abcd$`, "abcd", true},
		{"Go regex 11", nil, `^bcd'`, "abcdef", false},
		{"Go regex 12", nil, `^abcd$`, "abcde", false},
		{"Go regex 13", nil, `a+`, "baaab", true},
		{"Go regex 14", nil, `a*`, "baaab", true},
		{"Go regex 15", nil, `[a-z]+`, "abcd", true},
		{"Go regex 16", nil, `[^a-z]+`, "ab1234cd", true},
		{"Go regex 17", nil, `[a\-\]z]+`, "az]-bcz", true},
		{"Go regex 18", nil, `[^\n]+`, "abcd\n", true},
		{"Go regex 19", nil, `[日本語]+`, "日本語日本語", true},
		{"Go regex 20", nil, `日本語+`, "日本語", true},
		{"Go regex 21", nil, `日本語+`, "日本語語語語", true},
		{"Go regex 22", nil, `()`, "", true},
		{"Go regex 23", nil, `(a)`, "a", true},
		{"Go regex 24", nil, `(.)(.)`, "日a", true},
		{"Go regex 25", nil, `(.*)`, "", true},
		{"Go regex 26", nil, `(.*)`, "abcd", true},
		{"Go regex 27", nil, `(..)(..)`, "abcd", true},
		{"Go regex 28", nil, `(([^xyz]*)(d))`, "abcd", true},
		{"Go regex 29", nil, `((a|b|c)*(d))`, "abcd", true},
		{"Go regex 30", nil, `(((a|b|c)*)(d))`, "abcd", true},
		{"Go regex 31", nil, `\a\f\n\r\t\v`, "\a\f\n\r\t\v", true},
		{"Go regex 32", nil, `[\a\f\n\r\t\v]+`, "\a\f\n\r\t\v", true},

		// RE2 tests
		{"Go regex 33", nil, `[^\S\s]`, "abcd", false},
		{"Go regex 34", nil, `[^\S[:space:]]`, "abcd", false},
		{"Go regex 35", nil, `[^\D\d]`, "abcd", false},
		{"Go regex 36", nil, `[^\D[:digit:]]`, "abcd", false},
		{"Go regex 37", nil, `(?i)\W`, "x", false},
		{"Go regex 38", nil, `(?i)\W`, "k", false},
		{"Go regex 39", nil, `(?i)\W`, "s", false},

		// simple pattern definitions
		{"Go regex 1 with pattern", map[string]string{"PATTERN": "a+"}, `%{PATTERN}`, "baaab", true},

		{"Go regex 2 with pattern", map[string]string{"PATTERN": "abcd.."}, `%{PATTERN}`, "abcdef", true},
		{"Go regex 3 with pattern", map[string]string{"PATTERN": `a`}, `%{PATTERN}`, "a", true},
		{"Go regex 4 with pattern", map[string]string{"PATTERN": `x`}, `%{PATTERN}`, "y", false},
		{"Go regex 5 with pattern", map[string]string{"PATTERN": `b`}, `%{PATTERN}`, "abc", true},
		{"Go regex 6 with pattern", map[string]string{"PATTERN": `.`}, `%{PATTERN}`, "a", true},
		{"Go regex 7 with pattern", map[string]string{"PATTERN": `.*`}, `%{PATTERN}`, "abcdef", true},
		{"Go regex 8 with pattern", map[string]string{"PATTERN": `^`}, `%{PATTERN}`, "abcde", true},
		{"Go regex 9 with pattern", map[string]string{"PATTERN": `$`}, `%{PATTERN}`, "abcde", true},
		{"Go regex 10 with pattern", map[string]string{"PATTERN": `^abcd$`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 11 with pattern", map[string]string{"PATTERN": `^bcd'`}, `%{PATTERN}`, "abcdef", false},
		{"Go regex 12 with pattern", map[string]string{"PATTERN": `^abcd$`}, `%{PATTERN}`, "abcde", false},
		{"Go regex 13 with pattern", map[string]string{"PATTERN": `a+`}, `%{PATTERN}`, "baaab", true},
		{"Go regex 14 with pattern", map[string]string{"PATTERN": `a*`}, `%{PATTERN}`, "baaab", true},
		{"Go regex 15 with pattern", map[string]string{"PATTERN": `[a-z]+`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 16 with pattern", map[string]string{"PATTERN": `[^a-z]+`}, `%{PATTERN}`, "ab1234cd", true},
		{"Go regex 17 with pattern", map[string]string{"PATTERN": `[a\-\]z]+`}, `%{PATTERN}`, "az]-bcz", true},
		{"Go regex 18 with pattern", map[string]string{"PATTERN": `[^\n]+`}, `%{PATTERN}`, "abcd\n", true},
		{"Go regex 19 with pattern", map[string]string{"PATTERN": `[日本語]+`}, `%{PATTERN}`, "日本語日本語", true},
		{"Go regex 20 with pattern", map[string]string{"PATTERN": `日本語+`}, `%{PATTERN}`, "日本語", true},
		{"Go regex 21 with pattern", map[string]string{"PATTERN": `日本語+`}, `%{PATTERN}`, "日本語語語語", true},
		{"Go regex 22 with pattern", map[string]string{"PATTERN": `()`}, `%{PATTERN}`, "", true},
		{"Go regex 23 with pattern", map[string]string{"PATTERN": `(a)`}, `%{PATTERN}`, "a", true},
		{"Go regex 24 with pattern", map[string]string{"PATTERN": `(.)(.)`}, `%{PATTERN}`, "日a", true},
		{"Go regex 25 with pattern", map[string]string{"PATTERN": `(.*)`}, `%{PATTERN}`, "", true},
		{"Go regex 26 with pattern", map[string]string{"PATTERN": `(.*)`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 27 with pattern", map[string]string{"PATTERN": `(..)(..)`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 28 with pattern", map[string]string{"PATTERN": `(([^xyz]*)(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 29 with pattern", map[string]string{"PATTERN": `((a|b|c)*(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 30 with pattern", map[string]string{"PATTERN": `(((a|b|c)*)(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 31 with pattern", map[string]string{"PATTERN": `\a\f\n\r\t\v`}, `%{PATTERN}`, "\a\f\n\r\t\v", true},
		{"Go regex 32 with pattern", map[string]string{"PATTERN": `[\a\f\n\r\t\v]+`}, `%{PATTERN}`, "\a\f\n\r\t\v", true},

		// nested patterns
		{"hostname defined by nested patterns", map[string]string{
			"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
			"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
			"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			"NUMBER":             `\d+`,
			"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
			"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
		}, "%{NGINX_HOST}", "127.0.0.1:1234", true},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithoutDefaultPatterns()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, true))

			isMatch := g.MatchString(tt.Text)
			require.Equal(t, tt.ExpectedMatch, isMatch)
		})
	}
}

func TestParse(t *testing.T) {
	testCases := []struct {
		Name              string
		Patterns          map[string]string
		Pattern           string
		Text              string
		ExpectedMatches   map[string]string
		NamedCapturesOnly bool
	}{
		{
			"hostname defined by nested patterns",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"NUMBER":             `\d+`,
				"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
				"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
			},
			true,
		},

		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"NUMBER":             `\d+`,
				"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
				"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithoutDefaultPatterns()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))
			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestParseWithDefaultPatterns(t *testing.T) {
	testCases := []struct {
		Name                 string
		Patterns             map[string]string
		Pattern              string
		Text                 string
		ExpectedMatches      map[string]string
		ExpectedTypedMatches map[string]interface{}
		NamedCapturesOnly    bool
	}{
		{
			"hostname defined by nested patterns",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
			},
			nil,
			true,
		},

		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
				"BASE10NUM":        "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			nil,
			false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.New()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestTypedParseWithDefaultPatterns(t *testing.T) {
	testCases := []struct {
		Name                 string
		Patterns             map[string]string
		Pattern              string
		Text                 string
		ExpectedTypedMatches map[string]interface{}
		NamedCapturesOnly    bool
	}{
		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]interface{}{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
				"BASE10NUM":        "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			false,
		},

		{
			"hostname defined by nested patterns, typed port",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port:int})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"BOOL":               "true|false",
			},
			"%{NGINX_HOST} %{BOOL:destination.boolean:boolean}",
			"127.0.0.1:1234 true",
			map[string]interface{}{
				"destination.ip":      "127.0.0.1",
				"destination.port":    1234,
				"destination.boolean": true,
			},
			true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.New()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseTypedString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedTypedMatches), len(res))

			for k, v := range tt.ExpectedTypedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestDefaultPatterns(t *testing.T) {
	testCases := map[string][]string{
		"WORD":     {"hello", "world123", "test_data"},
		"NOTSPACE": {"example", "text-with-dashes", "12345"},
		"SPACE":    {" ", "\t", "  "},

		// types
		"INT":          {"123", "-456", "+789"},
		"NUMBER":       {"123", "456.789", "-0.123"},
		"BOOL":         {"true", "false", "true"},
		"BASE10NUM":    {"123", "-123.456", "0.789"},
		"BASE16NUM":    {"1a2b", "0x1A2B", "-0x1a2b3c"},
		"BASE16FLOAT":  {"0x1.a2b3", "-0x1A2B3C.D", "0x123.abc"},
		"POSINT":       {"123", "456", "789"},
		"NONNEGINT":    {"0", "123", "456"},
		"GREEDYDATA":   {"anything goes", "literally anything", "123 #@!"},
		"QUOTEDSTRING": {"\"This is a quote\"", "'single quoted'"},
		"UUID":         {"123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174001", "123e4567-e89b-12d3-a456-426614174002"},
		"URN":          {"urn:isbn:0451450523", "urn:ietf:rfc:2648", "urn:mpeg:mpeg7:schema:2001"},

		// network
		"IP":             {"192.168.1.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "172.16.254.1"},
		"IPV6":           {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "fe80::1ff:fe23:4567:890a"},
		"IPV4":           {"192.168.1.1", "10.0.0.1", "172.16.254.1"},
		"IPORHOST":       {"example.com", "192.168.1.1", "fe80::1ff:fe23:4567:890a"},
		"HOSTNAME":       {"example.com", "sub.domain.co.uk", "localhost"},
		"EMAILLOCALPART": {"john.doe", "alice123", "bob-smith"},
		"EMAILADDRESS":   {"john.doe@example.com", "alice123@domain.co.uk", "bob-smith@localhost"},
		"USERNAME":       {"user1", "john.doe", "alice_123"},
		"USER":           {"user1", "john.doe", "alice_123"},
		"MAC":            {"00:1A:2B:3C:4D:5E", "001A.2B3C.4D5E", "00-1A-2B-3C-4D-5E"},
		"CISCOMAC":       {"001A.2B3C.4D5E", "001B.2C3D.4E5F", "001C.2D3E.4F5A"},
		"WINDOWSMAC":     {"00-1A-2B-3C-4D-5E", "00-1B-2C-3D-4E-5F", "00-1C-2D-3E-4F-5A"},
		"COMMONMAC":      {"00:1A:2B:3C:4D:5E", "00:1B:2C:3D:4E:5F", "00:1C:2D:3E:4F:5A"},
		"HOSTPORT":       {"example.com:80", "192.168.1.1:8080"},

		// paths
		"UNIXPATH":     {"/home/user", "/var/log/syslog", "/tmp/abc_123"},
		"TTY":          {"/dev/pts/1", "/dev/tty0", "/dev/ttyS0"},
		"WINPATH":      {"C:\\Program Files\\App", "D:\\Work\\project\\file.txt", "E:\\New Folder\\test"},
		"URIPROTO":     {"http", "https", "ftp"},
		"URIHOST":      {"example.com", "192.168.1.1:8080"},
		"URIPATH":      {"/path/to/resource", "/another/path", "/root"},
		"URIQUERY":     {"key=value", "name=John&Doe", "search=query&active=true"},
		"URIPARAM":     {"?key=value", "?name=John&Doe", "?search=query&active=true"},
		"URIPATHPARAM": {"/path?query=1", "/resource?name=John", "/folder/path?valid=true"},
		"URI":          {"http://user:password@example.com:80/path?query=string", "https://example.com", "ftp://192.168.1.1/upload"},
		"PATH":         {"/home/user/documents", "C:\\Windows\\system32", "/var/log/syslog"},

		// dates
		"MONTH": {"January", "Feb", "March", "Apr", "May", "Jun", "Jul", "August", "September", "October", "Nov", "December"},

		// Months: January, Feb, 3, 03, 12, December "MONTH": `\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y|i)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b`,
		"MONTHNUM": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"},

		// Days Monday, Tue, Thu, etc
		"DAY": {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"},

		// Years?
		"YEAR":   {"1999", "2000", "2021"},
		"HOUR":   {"00", "12", "23"},
		"MINUTE": {"00", "30", "59"},

		// '60' is a leap second in most time standards and thus is valid.
		"SECOND": {"00", "30", "60"},
		"TIME":   {"14:30", "23:59:59", "12:00:00", "12:00:60"},

		// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
		"DATE_US":            {"04/21/2022", "12-25-2020", "07/04/1999"},
		"DATE_EU":            {"21.04.2022", "25/12/2020", "04-07-1999"},
		"ISO8601_TIMEZONE":   {"Z", "+02:00", "-05:00"},
		"ISO8601_SECOND":     {"59", "30", "60.123"},
		"TIMESTAMP_ISO8601":  {"2022-04-21T14:30:00Z", "2020-12-25T23:59:59+02:00", "1999-07-04T12:00:00-05:00"},
		"DATE":               {"04/21/2022", "21.04.2022", "12-25-2020"},
		"DATESTAMP":          {"04/21/2022 14:30", "21.04.2022 23:59", "12-25-2020 12:00"},
		"TZ":                 {"EST", "CET", "PDT"},
		"DATESTAMP_RFC822":   {"Wed Jan 12 2024 14:33 EST"},
		"DATESTAMP_RFC2822":  {"Tue, 12 Jan 2022 14:30 +0200", "Fri, 25 Dec 2020 23:59 -0500", "Sun, 04 Jul 1999 12:00 Z"},
		"DATESTAMP_OTHER":    {"Tue Jan 12 14:30 EST 2022", "Fri Dec 25 23:59 CET 2020", "Sun Jul 04 12:00 PDT 1999"},
		"DATESTAMP_EVENTLOG": {"20220421143000", "20201225235959", "19990704120000"},

		// Syslog Dates: Month Day HH:MM:SS	"MONTH":         `\b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|Mar(?:ch|z)?|Apr(?:il)?|May|i|Jun(?:e|i)?|Jul(?:y|i)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b`,
		"SYSLOGTIMESTAMP": {"Jan  1 00:00:00", "Mar 15 12:34:56", "Dec 31 23:59:59"},
		"PROG":            {"sshd", "kernel", "cron"},
		"SYSLOGPROG":      {"sshd[1234]", "kernel", "cron[5678]"},
		"SYSLOGHOST":      {"example.com", "192.168.1.1", "localhost"},
		"SYSLOGFACILITY":  {"<1.2>", "<12345.13456>"},
		"HTTPDATE":        {"25/Dec/2024:14:33 4"},
	}

	for name, values := range testCases {
		for i, sample := range values {
			t.Run(fmt.Sprintf("%s-%d", name, i), func(t *testing.T) {
				g := grok.New()

				pattern := fmt.Sprintf("%%{%s:result}", name)
				require.NoError(t, g.Compile(pattern, true))

				res, err := g.ParseString(sample)
				require.NoError(t, err)

				expKey := "result"
				val, found := res[expKey]
				require.True(t, found, "Key %q not found", expKey)
				require.Equal(t, sample, val)
			})
		}
	}
}
