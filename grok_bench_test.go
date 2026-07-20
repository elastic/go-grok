// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package grok_test

import (
	"testing"

	"github.com/elastic/go-grok"
	"github.com/elastic/go-grok/patterns"
)

const (
	benchApachePattern = `%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`
	benchApacheInput   = `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`
	benchFastNoMatch   = `!`
	benchLateNoMatch   = `127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 nope`

	benchNestedPattern = `%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}`
	benchNestedInput   = `127.0.0.1:1234 grok123 - grok123@elastic.co`

	benchAnchoredPattern = `%{PATTERN}`
	benchAnchoredInput   = `abcd`

	benchHTTPDPattern = `%{HTTPD_COMBINEDLOG}`
	benchHTTPDInput   = `127.0.0.1 user username [26/Jun/2024:12:34:56 -0700] "GET /index.html HTTP/1.1" 200 1234 "referrer" "Mozilla/5.0"`
)

var benchNestedPatterns = map[string]string{
	"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port:int})?`,
	"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
}

var benchAnchoredPatterns = map[string]string{
	"PATTERN": `^abcd$`,
}

var benchStartAnchoredPatterns = map[string]string{
	"PATTERN": `^bcd'`,
}

func BenchmarkGrokCompile(b *testing.B) {
	for _, tc := range []struct {
		name     string
		pattern  string
		patterns map[string]string
	}{
		{name: "simple", pattern: `%{WORD:word}`},
		{name: "apache", pattern: benchApachePattern},
		{name: "nested", pattern: benchNestedPattern, patterns: benchNestedPatterns},
		{name: "anchored_full", pattern: benchAnchoredPattern, patterns: benchAnchoredPatterns},
		{name: "anchored_start", pattern: benchAnchoredPattern, patterns: benchStartAnchoredPatterns},
		{name: "httpd", pattern: benchHTTPDPattern, patterns: patterns.Httpd},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				g := grok.New()
				if tc.patterns != nil {
					if err := g.AddPatterns(tc.patterns); err != nil {
						b.Fatal(err)
					}
				}
				if err := g.Compile(tc.pattern, true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGrokRecompileAnchored(b *testing.B) {
	for _, tc := range []struct {
		name     string
		patterns map[string]string
	}{
		{name: "full", patterns: benchAnchoredPatterns},
		{name: "start", patterns: benchStartAnchoredPatterns},
	} {
		b.Run(tc.name, func(b *testing.B) {
			g := newCompiledBenchGrok(b, benchAnchoredPattern, tc.patterns, true)

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if err := g.Compile(benchAnchoredPattern, true); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGrokMatchString(b *testing.B) {
	g := newCompiledBenchGrok(b, benchApachePattern, nil, true)

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchApacheInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: benchLateNoMatch},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_ = g.MatchString(tc.text)
			}
		})
	}
}

func BenchmarkGrokMatchStringAnchored(b *testing.B) {
	for _, tc := range []struct {
		name     string
		patterns map[string]string
		text     string
	}{
		{name: "full/match", patterns: benchAnchoredPatterns, text: benchAnchoredInput},
		{name: "full/no_match", patterns: benchAnchoredPatterns, text: "abcde"},
		{name: "start/no_match", patterns: benchStartAnchoredPatterns, text: "abcdef"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			g := newCompiledBenchGrok(b, benchAnchoredPattern, tc.patterns, true)

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_ = g.MatchString(tc.text)
			}
		})
	}
}

func BenchmarkGrokMatchBytes(b *testing.B) {
	g := newCompiledBenchGrok(b, benchApachePattern, nil, true)

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchApacheInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: benchLateNoMatch},
	} {
		b.Run(tc.name, func(b *testing.B) {
			text := []byte(tc.text)

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_ = g.Match(text)
			}
		})
	}
}

func BenchmarkGrokParseString(b *testing.B) {
	for _, namedCapturesOnly := range []bool{true, false} {
		name := "named_captures"
		if !namedCapturesOnly {
			name = "all_captures"
		}

		b.Run(name, func(b *testing.B) {
			g := newCompiledBenchGrok(b, benchApachePattern, nil, namedCapturesOnly)
			benchmarkParseStringCases(b, g)
		})
	}
}

func BenchmarkGrokParseBytes(b *testing.B) {
	g := newCompiledBenchGrok(b, benchApachePattern, nil, true)

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchApacheInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: benchLateNoMatch},
	} {
		b.Run(tc.name, func(b *testing.B) {
			text := []byte(tc.text)

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, err := g.Parse(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGrokParseTypedString(b *testing.B) {
	g := newCompiledBenchGrok(b, benchNestedPattern, benchNestedPatterns, true)
	benchmarkParseTypedStringCases(b, g)
}

func BenchmarkGrokParseTypedBytes(b *testing.B) {
	g := newCompiledBenchGrok(b, benchNestedPattern, benchNestedPatterns, true)

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchNestedInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: `127.0.0.1:1234 grok123 - not-an-email`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			text := []byte(tc.text)

			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, err := g.ParseTyped(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGrokParseStringHTTPD(b *testing.B) {
	g := newCompiledBenchGrok(b, benchHTTPDPattern, patterns.Httpd, true)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := g.ParseString(benchHTTPDInput); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGrokParseNoCapture(b *testing.B) {
	g := newCompiledBenchGrok(b, `foo`, nil, true)

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: "food"},
		{name: "no_match", text: "bar"},
	} {
		text := tc.text
		textBytes := []byte(text)
		for _, parser := range []struct {
			name  string
			parse func() error
		}{
			{"string", func() error {
				_, err := g.ParseString(text)
				return err
			}},
			{"bytes", func() error {
				_, err := g.Parse(textBytes)
				return err
			}},
			{"typed_string", func() error {
				_, err := g.ParseTypedString(text)
				return err
			}},
			{"typed_bytes", func() error {
				_, err := g.ParseTyped(textBytes)
				return err
			}},
		} {
			parser := parser
			b.Run(tc.name+"/"+parser.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					if err := parser.parse(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func benchmarkParseStringCases(b *testing.B, g *grok.Grok) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchApacheInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: benchLateNoMatch},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, err := g.ParseString(tc.text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkParseTypedStringCases(b *testing.B, g *grok.Grok) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "match", text: benchNestedInput},
		{name: "no_match_fast", text: benchFastNoMatch},
		{name: "no_match_late", text: `127.0.0.1:1234 grok123 - not-an-email`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, err := g.ParseTypedString(tc.text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func newCompiledBenchGrok(b testing.TB, pattern string, patternDefinitions map[string]string, namedCapturesOnly bool) *grok.Grok {
	b.Helper()

	g := grok.New()
	if patternDefinitions != nil {
		if err := g.AddPatterns(patternDefinitions); err != nil {
			b.Fatal(err)
		}
	}
	if err := g.Compile(pattern, namedCapturesOnly); err != nil {
		b.Fatal(err)
	}
	return g
}
