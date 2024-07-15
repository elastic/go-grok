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
	"github.com/stretchr/testify/require"
)

func TestParseWithPatterns_Bind9(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"BIND9 TIMESTAMP",
			"%{BIND9_TIMESTAMP}",
			"18-Jun-24 12:34:56",
			map[string]string{
				"MONTHDAY": "18",
				"MONTH":    "Jun",
				"YEAR":     "24",
				"TIME":     "12:34:56",
			},
		},
		{
			"BIND9 DNSTYPE",
			"%{BIND9_DNSTYPE}",
			"A",
			map[string]string{
				"BIND9_DNSTYPE": "A",
			},
		},
		{
			"BIND9 CATEGORY",
			"%{BIND9_CATEGORY}",
			"queries",
			map[string]string{
				"BIND9_CATEGORY": "queries",
			},
		},
		{
			"BIND9 QUERY LOG BASE",
			"%{BIND9_QUERYLOGBASE}",
			"client @0x1234567890 192.168.1.100#53245 (example.com): query: www.example.com IN A UDP (192.0.2.1)",
			map[string]string{
				"client.address":         "192.168.1.100",
				"client.port":            "53245",
				"bind.log.question.name": "example.com",
				"dns.question.name":      "www.example.com",
				"dns.question.class":     "IN",
				"dns.question.type":      "A",
				"server.address":         "192.0.2.1",
			},
		},
		{
			"BIND9 QUERY LOG",
			"%{BIND9_QUERYLOG}",
			"18-Jun-2024 12:34:56 queries: INFO: client @0x1234567890 192.168.1.100#53245 (example.com): query: www.example.com IN A UDP (192.0.2.1)",
			map[string]string{
				"timestamp":              "18-Jun-2024 12:34:56",
				"bing.log.category":      "queries",
				"log.level":              "INFO",
				"client.address":         "192.168.1.100",
				"client.port":            "53245",
				"bind.log.question.name": "example.com",
				"dns.question.name":      "www.example.com",
				"dns.question.class":     "IN",
				"dns.question.type":      "A",
				"server.address":         "192.0.2.1",
			},
		},
		{
			"BIND9",
			"%{BIND9}",
			"18-Jun-2024 12:34:56 queries: INFO: client @0x1234567890 192.168.1.100#53245 (example.com): query: www.example.com IN A UDP (192.0.2.1)",
			map[string]string{
				"timestamp":              "18-Jun-2024 12:34:56",
				"bing.log.category":      "queries",
				"log.level":              "INFO",
				"bind.log.question.name": "example.com",
				"dns.question.name":      "www.example.com",
				"dns.question.class":     "IN",
				"dns.question.type":      "A",
				"client.address":         "192.168.1.100",
				"client.port":            "53245",
				"server.address":         "192.0.2.1",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Bind9)
			require.NoError(t, g.Compile(tt.Pattern, false))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}
