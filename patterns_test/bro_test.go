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

package patterns_test

import (
	"testing"

	"github.com/elastic/go-grok"
	"github.com/elastic/go-grok/patterns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWithPatterns_Bro(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"BRO BOOL",
			"%{BRO_BOOL}",
			"T",
			map[string]string{
				"BRO_BOOL": "T",
			},
		},
		{
			"BRO DATA",
			"%{BRO_DATA}",
			"example_data_here",
			map[string]string{
				"BRO_DATA": "example_data_here",
			},
		},
		{
			"BRO HTTP",
			"%{BRO_HTTP}",
			"1234567890\tsession123\t192.168.1.100\t53245\t192.0.2.1\t80\t1\tGET\texample.com\thttps://example.com/path\treff\tMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36\t1024\t2048\t200\tOK\t200\tOK\tfile.txt\t(empty)\tusername\t-\t-\t-\tapplication/json\t-\t-\ttext/html",
			map[string]string{
				"timestamp":                 "1234567890",
				"zeek.session_id":           "session123",
				"source.address":            "192.168.1.100",
				"source.port":               "53245",
				"destination.address":       "192.0.2.1",
				"destination.port":          "80",
				"zeek.http.trans_depth":     "1",
				"http.request.method":       "GET",
				"url.domain":                "example.com",
				"url.original":              "https://example.com/path",
				"http.request.referrer":     "reff",
				"user_agent.original":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36",
				"http.request.body.size":    "1024",
				"http.response.body.size":   "2048",
				"http.response.status_code": "200",
				"zeek.http.status_msg":      "OK",
				"zeek.http.info_code":       "200",
				"zeek.http.info_msg":        "OK",
				"zeek.http.filename":        "file.txt",
				"url.username":              "username",
			},
		},
		{
			"BRO_DNS",
			"%{BRO_DNS}",
			"1623847260.25348\tsession456\t192.168.1.50\t12345\t192.0.2.50\t53\tudp\t1234\twww.example.com\t1\tIN\t1\tA\t0\tNOERROR\tT\tF\tT\tT\t0\t192.0.2.51\t60.0\tF",
			map[string]string{
				"timestamp":            "1623847260.25348",
				"zeek.session_id":      "session456",
				"source.address":       "192.168.1.50",
				"source.port":          "12345",
				"destination.address":  "192.0.2.50",
				"destination.port":     "53",
				"network.transport":    "udp",
				"dns.id":               "1234",
				"dns.question.name":    "www.example.com",
				"zeek.dns.qclass":      "1",
				"zeek.dns.qclass_name": "IN",
				"zeek.dns.qtype":       "1",
				"dns.question.type":    "A",
				"zeek.dns.rcode":       "0",
				"dns.response_code":    "NOERROR",
				"zeek.dns.AA":          "T",
				"zeek.dns.TC":          "F",
				"zeek.dns.RD":          "T",
				"zeek.dns.RA":          "T",
				"zeek.dns.Z":           "0",
				"zeek.dns.answers":     "192.0.2.51",
				"zeek.dns.TTLs":        "60.0",
				"zeek.dns.rejected":    "F",
			},
		},
		{
			"BRO_CONN",
			"%{BRO_CONN}",
			"1623847260.25348\tsession123\t192.168.1.100\t12345\t192.0.2.100\t80\ttcp\thttp\t10.5\t5000\t6000\tRSTO\tT\tF\t200\tShADadF\t10\t5000\t15\t6000\ttunnel_parents",
			map[string]string{
				"timestamp":                      "1623847260.25348",
				"zeek.session_id":                "session123",
				"source.address":                 "192.168.1.100",
				"source.port":                    "12345",
				"destination.address":            "192.0.2.100",
				"destination.port":               "80",
				"network.transport":              "tcp",
				"network.protocol.name":          "http",
				"zeek.connection.duration":       "10.5",
				"zeek.connection.orig_bytes":     "5000",
				"zeek.connection.resp_bytes":     "6000",
				"zeek.connection.state":          "RSTO",
				"zeek.connection.local_orig":     "T",
				"zeek.connection.local_resp":     "F",
				"zeek.connection.missed_bytes":   "200",
				"zeek.connection.history":        "ShADadF",
				"source.packets":                 "10",
				"source.bytes":                   "5000",
				"destination.packets":            "15",
				"destination.bytes":              "6000",
				"zeek.connection.tunnel_parents": "tunnel_parents",
			},
		},
		{
			"BRO_FILES",
			"%{BRO_FILES}",
			"1623847260.25348\tF123abc\t192.0.2.100\t192.168.1.100\tsession123\tHTTP\t2\tanalyzer1\tapplication/pdf\tfile1.pdf\t0.5\tlocal\tT\t1024\t2048\t0\t0\tF\tparent_fuid1\t5d41402abc4b2a76b9719d911017c592\t2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\t3f79bb7b435b05321651daefd374cd21b89a2935\t/tmp/file1.pdf",
			map[string]string{
				"timestamp":                 "1623847260.25348",
				"zeek.files.fuid":           "F123abc",
				"server.address":            "192.0.2.100",
				"client.address":            "192.168.1.100",
				"zeek.files.session_ids":    "session123",
				"zeek.files.source":         "HTTP",
				"zeek.files.depth":          "2",
				"zeek.files.analyzers":      "analyzer1",
				"file.mime_type":            "application/pdf",
				"file.name":                 "file1.pdf",
				"zeek.files.duration":       "0.5",
				"zeek.files.local_orig":     "local",
				"zeek.files.is_orig":        "T",
				"zeek.files.seen_bytes":     "1024",
				"file.size":                 "2048",
				"zeek.files.missing_bytes":  "0",
				"zeek.files.overflow_bytes": "0",
				"zeek.files.timedout":       "F",
				"zeek.files.parent_fuid":    "parent_fuid1",
				"file.hash.md5":             "5d41402abc4b2a76b9719d911017c592",
				"file.hash.sha1":            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
				"file.hash.sha256":          "3f79bb7b435b05321651daefd374cd21b89a2935",
				"zeek.files.extracted":      "/tmp/file1.pdf",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.Bro)
			require.NoError(t, err)
			require.NoError(t, g.Compile(tt.Pattern, false))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			if len(tt.ExpectedMatches) > len(res) {
				for k := range tt.ExpectedMatches {
					_, ok := res[k]
					assert.Truef(t, ok, "key not found %q", k)
				}
			}

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equalf(t, v, val, "Values not equal for key. Expected %q, have %q", k, v, val)
			}
		})
	}
}
