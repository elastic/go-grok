package benchmarks_test

import (
	"regexp"
	"testing"

	"github.com/elastic/go-grok"
	"github.com/stretchr/testify/require"
	tgrok "github.com/trivago/grok"
	vgrok "github.com/vjeantet/grok"
)

// Comparison benchmarks

func BenchmarkParseString(b *testing.B) {
	g := grok.New()
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	err := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`, true)
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		g.ParseString(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	}
}

func BenchmarkParseStringRegexp(b *testing.B) {
	c := regexp.MustCompile("(?P<clientip>(?:(\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\\.?|\\b))|((?:(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?)|((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))))) (?P<ident>([a-zA-Z0-9._-]+)) (?P<auth>([a-zA-Z0-9._-]+)) \\[(?P<timestamp>((?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]))/(\\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\b)/((\\d\\d){1,2}):(([^0-9]?)((?:2[0123]|[01]?[0-9])):((?:[0-5][0-9]))(?::((?:(?:[0-5][0-9]|60)(?:[:.,][0-9]+)?)))([^0-9]?)) ((?:[+-]?(?:[0-9]+))))\\] \"(?:(?P<verb>\\b\\w+\\b) (?P<request>\\S+)(?: HTTP/(?P<httpversion>(?:(([+-]?(?:[0-9]+(?:\\.[0-9]+)?)|\\.[0-9]+)))))?|(?P<rawrequest>.*?))\" (?P<response>(?:(([+-]?(?:[0-9]+(?:\\.[0-9]+)?)|\\.[0-9]+)))) (?:(?P<bytes>(?:(([+-]?(?:[0-9]+(?:\\.[0-9]+)?)|\\.[0-9]+))))|-)")
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times

	for n := 0; n < b.N; n++ {
		c.FindAllStringSubmatch(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`, -1)
	}
}

func BenchmarkParseStringTrivago(b *testing.B) {
	g, _ := tgrok.New(tgrok.Config{NamedCapturesOnly: true})
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile(`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`)
	for n := 0; n < b.N; n++ {
		c.ParseString(`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`)
	}
}

func BenchmarkParseStringVjeanet(b *testing.B) {
	g, _ := vgrok.New()
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	for n := 0; n < b.N; n++ {
		g.Parse(
			`%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`,
			`127.0.0.1 - - [23/Apr/2014:22:58:32 +0200] "GET /index.php HTTP/1.1" 404 207`,
		)
	}
}

func BenchmarkNestedParseString(b *testing.B) {
	g := grok.New()
	g.AddPatterns(map[string]string{
		"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port})?`,
		"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
	})
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	err := g.Compile("%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}", true)
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		g.ParseString(`127.0.0.1:1234 grok123 - grok123@elastic.co`)
	}
}

func BenchmarkNestedParseStringTrivago(b *testing.B) {
	g, err := tgrok.New(tgrok.Config{
		NamedCapturesOnly: true,
		Patterns: map[string]string{
			"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port})?`,
			"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
		},
	})
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile("%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}")
	for n := 0; n < b.N; n++ {
		c.ParseString(`127.0.0.1:1234 grok123 - grok123@elastic.co`)
	}
}

func BenchmarkNestedParseStringVjeanet(b *testing.B) {
	g, _ := vgrok.New()
	err := g.AddPatternsFromMap(map[string]string{
		"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port})?`,
		"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
	})
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	for n := 0; n < b.N; n++ {
		g.Parse(
			"%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}",
			`127.0.0.1:1234 grok123 - grok123@elastic.co`,
		)
	}
}

func BenchmarkTypedParseString(b *testing.B) {
	g := grok.New()
	g.AddPatterns(map[string]string{
		"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port:int})?`,
		"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
	})
	input := []byte(`127.0.0.1:1234 grok123 - grok123@elastic.co`)

	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	err := g.Compile("%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}", true)
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		m, e := g.ParseTyped(input)
		require.True(b, len(m) > 0)
		require.NoError(b, e)
	}
}

func BenchmarkTypedParseStringTrivago(b *testing.B) {
	g, err := tgrok.New(tgrok.Config{
		NamedCapturesOnly: true,
		Patterns: map[string]string{
			"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port:int})?`,
			"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
		},
	})
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	c, _ := g.Compile("%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}")
	for n := 0; n < b.N; n++ {
		m, _ := c.ParseStringTyped(`127.0.0.1:1234 grok123 - grok123@elastic.co`)
		require.True(b, len(m) > 0)
	}
}

func BenchmarkTypedParseStringVjeanet(b *testing.B) {
	g, _ := vgrok.New()
	err := g.AddPatternsFromMap(map[string]string{
		"NGINX_HOST":         `(?:%{IP:destination__ip}|%{NGINX_NOTSEPARATOR:destination__domain})(:%{NUMBER:destination__port:int})?`,
		"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
	})
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	// run the check function b.N times
	for n := 0; n < b.N; n++ {
		m, e := g.ParseTyped(
			"%{NGINX_HOST} %{USERNAME} - %{EMAILADDRESS}",
			`127.0.0.1:1234 grok123 - grok123@elastic.co`,
		)
		require.True(b, len(m) > 0)
		require.NoError(b, e)
	}
}
