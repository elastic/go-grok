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

func TestParseWithPatterns_Junos(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		// {
		// 	"RT_FLOW_TAG",
		// 	"%{RT_FLOW_TAG}",
		// 	"RT_FLOW_SESSION_CREATE",
		// 	map[string]string{
		// 		"RT_FLOW_TAG": "RT_FLOW_SESSION_CREATE",
		// 	},
		// },
		// {
		// 	"RT_FLOW_EVENT",
		// 	"%{RT_FLOW_EVENT}",
		// 	"RT_FLOW_SESSION_CLOSE",
		// 	map[string]string{
		// 		"RT_FLOW_EVENT": "RT_FLOW_SESSION_CLOSE",
		// 	},
		// },
		// {
		// 	"RT_FLOW1",
		// 	"%{RT_FLOW1}",
		// 	"RT_FLOW_SESSION_CREATE: Traffic allowed: 192.168.1.1/12345->10.0.0.1/80 HTTP 192.168.1.10/54321->10.0.0.10/8080 - - 6 policy1 trust untrust 123456 12345(1500) 67890(3000) 200 45",
		// 	map[string]string{
		// 		"juniper.srx.tag":          "RT_FLOW_SESSION_CREATE",
		// 		"juniper.srx.reason":       "Traffic allowed",
		// 		"source.ip":                "192.168.1.1",
		// 		"source.port":              "12345",
		// 		"destination.ip":           "10.0.0.1",
		// 		"destination.port":         "80",
		// 		"juniper.srx.service_name": "HTTP",
		// 		"source.nat.ip":            "192.168.1.10",
		// 		"source.nat.port":          "54321",
		// 		"destination.nat.ip":       "10.0.0.10",
		// 		"destination.nat.port":     "8080",
		// 		"network.iana_number":      "6",
		// 		"rule.name":                "policy1",
		// 		"observer.ingress.zone":    "trust",
		// 		"observer.egress.zone":     "untrust",
		// 		"juniper.srx.session_id":   "123456",
		// 		"source.bytes":             "1500",
		// 		"destination.bytes":        "3000",
		// 		"juniper.srx.elapsed_time": "200",
		// 	},
		// },
		{
			"RT_FLOW2",
			"%{RT_FLOW2}",
			"RT_FLOW_SESSION_CREATE: session created 192.168.1.1/12345->10.0.0.1/80 HTTP 192.168.1.10/54321->10.0.0.10/8080 None None 6 policy1 trust untrust 123456 rest",
			map[string]string{
				"juniper.srx.tag":          "RT_FLOW_SESSION_CREATE",
				"source.ip":                "192.168.1.1",
				"source.port":              "12345",
				"destination.ip":           "10.0.0.1",
				"destination.port":         "80",
				"juniper.srx.service_name": "HTTP",
				"source.nat.ip":            "192.168.1.10",
				"source.nat.port":          "54321",
				"destination.nat.ip":       "10.0.0.10",
				"destination.nat.port":     "8080",
				"network.iana_number":      "6",
				"rule.name":                "policy1",
				"observer.ingress.zone":    "trust",
				"observer.egress.zone":     "untrust",
				"juniper.srx.session_id":   "123456",
			},
		},
		{
			"RT_FLOW3",
			"%{RT_FLOW3}",
			"RT_FLOW_SESSION_DENY: session denied 192.168.1.1/12345->10.0.0.1/80 HTTP 6(1) policy2 trust untrust rest",
			map[string]string{
				"juniper.srx.tag":          "RT_FLOW_SESSION_DENY",
				"source.ip":                "192.168.1.1",
				"source.port":              "12345",
				"destination.ip":           "10.0.0.1",
				"destination.port":         "80",
				"juniper.srx.service_name": "HTTP",
				"network.iana_number":      "6",
				"rule.name":                "policy2",
				"observer.ingress.zone":    "trust",
				"observer.egress.zone":     "untrust",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Junos)
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
