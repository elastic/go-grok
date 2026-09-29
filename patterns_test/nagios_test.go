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

func TestParseWithPatterns_Nagios(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"NAGIOSTIME",
			`%{NAGIOSTIME}`,
			"[1234567890]",
			map[string]string{
				"timestamp": "1234567890",
			},
		},
		{
			"NAGIOS_SERVICE_ALERT",
			`%{NAGIOS_SERVICE_ALERT}`,
			"SERVICE ALERT: localhost;HTTP;CRITICAL;HARD;3;Connection refused",
			map[string]string{
				"nagios.log.type":       "SERVICE ALERT",
				"host.hostname":         "localhost",
				"service.name":          "HTTP",
				"service.state":         "CRITICAL",
				"nagios.log.state_type": "HARD",
				"nagios.log.attempt":    "3",
				"message":               "Connection refused",
			},
		},
		{
			"NAGIOS_HOST_ALERT",
			`%{NAGIOS_HOST_ALERT}`,
			"HOST ALERT: web01;DOWN;SOFT;1;PING CRITICAL",
			map[string]string{
				"nagios.log.type":       "HOST ALERT",
				"host.hostname":         "web01",
				"service.state":         "DOWN",
				"nagios.log.state_type": "SOFT",
				"nagios.log.attempt":    "1",
				"message":               "PING CRITICAL",
			},
		},
		{
			"NAGIOSLOGLINE",
			`%{NAGIOSLOGLINE}`,
			"[1234567890] SERVICE ALERT: localhost;HTTP;CRITICAL;HARD;3;Connection refused",
			map[string]string{
				"timestamp":             "1234567890",
				"nagios.log.type":       "SERVICE ALERT",
				"host.hostname":         "localhost",
				"service.name":          "HTTP",
				"service.state":         "CRITICAL",
				"nagios.log.state_type": "HARD",
				"nagios.log.attempt":    "3",
				"message":               "Connection refused",
			},
		},
		{
			"NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT",
			`%{NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT}`,
			"EXTERNAL COMMAND: PROCESS_SERVICE_CHECK_RESULT;web01;Disk;0;OK - free space",
			map[string]string{
				"nagios.log.type":         "EXTERNAL COMMAND",
				"nagios.log.command":      "PROCESS_SERVICE_CHECK_RESULT",
				"host.hostname":           "web01",
				"service.name":            "Disk",
				"service.state":           "0",
				"nagios.log.check_result": "OK - free space",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.Nagios)
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
