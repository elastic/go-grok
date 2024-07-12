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

func TestParseWithPatterns_HAProxy(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"HAPROXYTIME",
			"%{HAPROXYTIME}",
			`12:34:56`,
			map[string]string{
				"HOUR":   "12",
				"MINUTE": "34",
				"SECOND": "56",
			},
		},
		{
			"HAPROXYDATE",
			"%{HAPROXYDATE}",
			`18/Jun/2023:12:34:56.789`,
			map[string]string{
				"MONTHDAY":    "18",
				"MONTH":       "Jun",
				"YEAR":        "2023",
				"HAPROXYTIME": "12:34:56",
				"INT":         "789",
			},
		},
		{
			"HAPROXYCAPTUREDREQUESTHEADERS",
			"({%{HAPROXYCAPTUREDREQUESTHEADERS}})",
			`{User-Agent: curl/7.68.0 Accept: */*}`,
			map[string]string{
				"haproxy.http.request.captured_headers": "User-Agent: curl/7.68.0 Accept: */*",
			},
		},
		{
			"HAPROXYCAPTUREDRESPONSEHEADERS",
			"({%{HAPROXYCAPTUREDRESPONSEHEADERS}})",
			`{Content-Type: text/html; charset=UTF-8 Server: Apache}`,
			map[string]string{
				"haproxy.http.response.captured_headers": "Content-Type: text/html; charset=UTF-8 Server: Apache",
			},
		},
		{
			"HAPROXYURI",
			"%{HAPROXYURI}",
			`https://user:pass@www.example.com:8080/path?query=123`,
			map[string]string{
				"url.scheme":   "https",
				"url.username": "user",
				"url.domain":   "www.example.com",
				"url.port":     "8080",
				"url.path":     "/path",
				"url.query":    "query=123",
			},
		},
		{
			"HAPROXYHTTPREQUESTLINE",
			"%{HAPROXYHTTPREQUESTLINE}",
			`GET https://user:pass@www.example.com:8080/path?query=123 HTTP/1.1`,
			map[string]string{
				"http.request.method": "GET",
				"url.original":        "https://user:pass@www.example.com:8080/path?query=123",
				"http.version":        "1.1",
			},
		},
		{
			"HAPROXYHTTPBASE",
			"%{HAPROXYHTTPBASE}",
			`192.168.0.1:12345 [26/Jun/2024:15:23:45.678] frontend backend/server 10/20/30/40/50 200 1234 - - sD 2/3/4/5/6 7/8 {header1:value1 header2:value2} {header3:value3 header4:value4} "GET https://user:pass@www.example.com:8080/path?query=123 HTTP/1.1"`,
			map[string]string{
				"source.address":                                 "192.168.0.1",
				"source.port":                                    "12345",
				"haproxy.request_date":                           "26/Jun/2024:15:23:45.678",
				"haproxy.frontend_name":                          "frontend",
				"haproxy.backend_name":                           "backend",
				"haproxy.server_name":                            "server",
				"haproxy.http.request.time_wait_ms":              "10",
				"haproxy.total_waiting_time_ms":                  "20",
				"haproxy.connection_wait_time_ms":                "30",
				"haproxy.http.request.time_wait_without_data_ms": "40",
				"haproxy.total_time_ms":                          "50",
				"http.response.status_code":                      "200",
				"source.bytes":                                   "1234",
				"haproxy.termination_state":                      "sD",
				"haproxy.connections.active":                     "2",
				"haproxy.connections.frontend":                   "3",
				"haproxy.connections.backend":                    "4",
				"haproxy.connections.server":                     "5",
				"haproxy.connections.retries":                    "6",
				"haproxy.server_queue":                           "7",
				"haproxy.backend_queue":                          "8",
				"HAPROXYCAPTUREDREQUESTHEADERS":                  "header1:value1 header2:value2",
				"HAPROXYCAPTUREDRESPONSEHEADERS":                 "header3:value3 header4:value4",
				"HAPROXYHTTPREQUESTLINE":                         `GET https://user:pass@www.example.com:8080/path?query=123 HTTP/1.1`,
			},
		},
		{
			"HAPROXYHTTP",
			"%{HAPROXYHTTP}",
			`Jun 18 12:34:56 host haproxy: 192.168.0.1:12345 [26/Jun/2024:15:23:45.678] frontend backend/server 10/20/30/40/50 200 1234 - - sD 2/3/4/5/6 7/8 {header1:value1 header2:value2} {header3:value3 header4:value4} "GET https://user:pass@www.example.com:8080/path?query=123 HTTP/1.1"`,
			map[string]string{
				"timestamp":                                      "Jun 18 12:34:56",
				"host.name":                                      "host",
				"SYSLOGPROG":                                     "haproxy",
				"source.address":                                 "192.168.0.1",
				"source.port":                                    "12345",
				"haproxy.request_date":                           "26/Jun/2024:15:23:45.678",
				"haproxy.frontend_name":                          "frontend",
				"haproxy.backend_name":                           "backend",
				"haproxy.server_name":                            "server",
				"haproxy.http.request.time_wait_ms":              "10",
				"haproxy.total_waiting_time_ms":                  "20",
				"haproxy.connection_wait_time_ms":                "30",
				"haproxy.http.request.time_wait_without_data_ms": "40",
				"haproxy.total_time_ms":                          "50",
				"http.response.status_code":                      "200",
				"source.bytes":                                   "1234",
				"haproxy.termination_state":                      "sD",
				"haproxy.connections.active":                     "2",
				"haproxy.connections.frontend":                   "3",
				"haproxy.connections.backend":                    "4",
				"haproxy.connections.server":                     "5",
				"haproxy.connections.retries":                    "6",
				"haproxy.server_queue":                           "7",
				"haproxy.backend_queue":                          "8",
				"HAPROXYCAPTUREDREQUESTHEADERS":                  "header1:value1 header2:value2",
				"HAPROXYCAPTUREDRESPONSEHEADERS":                 "header3:value3 header4:value4",
				"HAPROXYHTTPREQUESTLINE":                         `GET https://user:pass@www.example.com:8080/path?query=123 HTTP/1.1`,
			},
		},
		{
			"HAPROXYTCP",
			"%{HAPROXYTCP}",
			`Jun 18 12:34:56 host haproxy: 192.168.0.1:12345 [18/Jun/2023:12:34:56.789] frontend backend/server 20/30/50 1000 ---- 5/10/15/20/25 0/0`,
			map[string]string{
				"timestamp":                       "Jun 18 12:34:56",
				"host.name":                       "host",
				"haproxy.frontend_name":           "frontend",
				"haproxy.backend_name":            "backend",
				"haproxy.server_name":             "server",
				"haproxy.total_waiting_time_ms":   "20",
				"haproxy.connection_wait_time_ms": "30",
				"haproxy.total_time_ms":           "50",
				"source.bytes":                    "1000",
				"haproxy.termination_state":       "----",
				"haproxy.connections.active":      "5",
				"haproxy.connections.frontend":    "10",
				"haproxy.connections.backend":     "15",
				"haproxy.connections.server":      "20",
				"haproxy.connections.retries":     "25",
				"haproxy.server_queue":            "0",
				"haproxy.backend_queue":           "0",
				"source.address":                  "192.168.0.1",
				"source.port":                     "12345",
				"haproxy.request_date":            "18/Jun/2023:12:34:56.789",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.HAProxy)
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
