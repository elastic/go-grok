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

func TestParseWithPatterns_Squid(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"SQUID3_STATUS",
			"%{SQUID3_STATUS}",
			"200",
			map[string]string{
				"http.response.status_code": "200",
			},
		},
		{
			"SQUID3",
			"%{SQUID3}",
			"1624624800.123 1500 192.168.1.1 TCP_MISS/200 5120 GET http://example.com elastic DIRECT/93.184.216.34 text/html",
			map[string]string{
				"timestamp":                 "1624624800.123",
				"squid.request.duration":    "1500",
				"source.address":            "192.168.1.1",
				"event.action":              "TCP_MISS",
				"http.response.status_code": "200",
				"http.response.bytes":       "5120",
				"http.request.method":       "GET",
				"url.original":              "http://example.com",
				"user.name":                 "elastic",
				"squid.hierarchy_code":      "DIRECT",
				"destination.address":       "93.184.216.34",
				"http.response.mime_type":   "text/html",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.Squid)
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
