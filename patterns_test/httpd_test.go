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

func TestParseWithPatterns_Httpd(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"HTTPDUSER",
			`%{HTTPDUSER}`,
			"user@example.com",
			map[string]string{
				"HTTPDUSER": "user@example.com",
			},
		},
		{
			"HTTPDERROR_DATE",
			`%{HTTPDERROR_DATE}`,
			"Wed Jun 26 12:34:56 2024",
			map[string]string{
				"HTTPDERROR_DATE": "Wed Jun 26 12:34:56 2024",
			},
		},
		{
			"HTTPD_COMMONLOG",
			`%{HTTPD_COMMONLOG}`,
			"127.0.0.1 user username [26/Jun/2024:12:34:56 -0700] \"GET /index.html HTTP/1.1\" 200 1234",
			map[string]string{
				"source.address":              "127.0.0.1",
				"apache.access.user.identity": "user",
				"user.name":                   "username",
				"timestamp":                   "26/Jun/2024:12:34:56 -0700",
				"http.request.method":         "GET",
				"url.original":                "/index.html",
				"http.version":                "1.1",
				"http.response.status_code":   "200",
				"http.response.body.bytes":    "1234",
			},
		},
		{
			"HTTPD_COMBINEDLOG",
			`%{HTTPD_COMBINEDLOG}`,
			"127.0.0.1 user username [26/Jun/2024:12:34:56 -0700] \"GET /index.html HTTP/1.1\" 200 1234 \"referrer\" \"Mozilla/5.0\"",
			map[string]string{
				"source.address":              "127.0.0.1",
				"apache.access.user.identity": "user",
				"user.name":                   "username",
				"timestamp":                   "26/Jun/2024:12:34:56 -0700",
				"http.request.method":         "GET",
				"url.original":                "/index.html",
				"http.version":                "1.1",
				"http.response.status_code":   "200",
				"http.response.body.bytes":    "1234",
				"user_agent.original":         "Mozilla/5.0",
				"http.request.referrer":       "referrer",
			},
		},
		{
			"HTTPD20_ERRORLOG",
			`%{HTTPD20_ERRORLOG}`,
			"[Wed Jun 26 12:34:56 2024] [error] [client 127.0.0.1] File does not exist",
			map[string]string{
				"timestamp":      "Wed Jun 26 12:34:56 2024",
				"log.level":      "error",
				"source.address": "127.0.0.1",
				"message":        "File does not exist",
			},
		},
		{
			"HTTPD24_ERRORLOG",
			`%{HTTPD24_ERRORLOG}`,
			"[Wed Jun 26 12:34:56 2024] [core:error] [pid 12345:tid 4567] (70007)The timeout specified has expired: [client 192.168.1.1:54321] AH00124: Request exceeded the limit",
			map[string]string{
				"timestamp":                        "Wed Jun 26 12:34:56 2024",
				"apache.error.module":              "core",
				"log.level":                        "error",
				"process.pid":                      "12345",
				"process.thread.id":                "4567",
				"apache.error.proxy.error.code":    "70007",
				"apache.error.proxy.error.message": "The timeout specified has expired",
				"source.address":                   "192.168.1.1",
				"source.port":                      "54321",
				"error.code":                       "AH00124",
				"message":                          "Request exceeded the limit",
			},
		},
		{
			"HTTPD_ERRORLOG",
			`%{HTTPD_ERRORLOG}`,
			"[Wed Jun 26 12:34:56 2024] [error] [client 127.0.0.1] File does not exist",
			map[string]string{
				"timestamp":      "Wed Jun 26 12:34:56 2024",
				"log.level":      "error",
				"source.address": "127.0.0.1",
				"message":        "File does not exist",
			},
		},
		{
			"COMMONAPACHELOG",
			`%{COMMONAPACHELOG}`,
			"127.0.0.1 user username [26/Jun/2024:12:34:56 -0700] \"GET /index.html HTTP/1.1\" 200 1234",
			map[string]string{
				"source.address":              "127.0.0.1",
				"apache.access.user.identity": "user",
				"user.name":                   "username",
				"timestamp":                   "26/Jun/2024:12:34:56 -0700",
				"http.request.method":         "GET",
				"url.original":                "/index.html",
				"http.version":                "1.1",
				"http.response.status_code":   "200",
				"http.response.body.bytes":    "1234",
			},
		},
		{
			"COMBINEDAPACHELOG",
			`%{COMBINEDAPACHELOG}`,
			"127.0.0.1 user username [26/Jun/2024:12:34:56 -0700] \"GET /index.html HTTP/1.1\" 200 1234 \"referrer\" \"Mozilla/5.0\"",
			map[string]string{
				"source.address":              "127.0.0.1",
				"apache.access.user.identity": "user",
				"user.name":                   "username",
				"timestamp":                   "26/Jun/2024:12:34:56 -0700",
				"http.request.method":         "GET",
				"url.original":                "/index.html",
				"http.version":                "1.1",
				"http.response.status_code":   "200",
				"http.response.body.bytes":    "1234",
				"user_agent.original":         "Mozilla/5.0",
				"http.request.referrer":       "referrer",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Httpd)
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
