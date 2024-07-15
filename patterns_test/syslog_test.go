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

func TestParseWithPatterns_Syslog(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"SYSLOG5424PRINTASCII",
			`%{SYSLOG5424PRINTASCII}`,
			"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			map[string]string{
				"SYSLOG5424PRINTASCII": "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			},
		},
		{
			"SYSLOGBASE2",
			`%{SYSLOGBASE2}`,
			"2024-06-26T12:34:56-0700 myhost program:",
			map[string]string{
				"timestamp":  "2024-06-26T12:34:56-0700",
				"host.name":  "myhost",
				"SYSLOGPROG": "program",
			},
		},
		{
			"SYSLOGPAMSESSION",
			`%{SYSLOGPAMSESSION}`,
			"Jun 26 12:34:56 myhost program: pam_unix(sshd session): session opened for user john by doe",
			map[string]string{
				"timestamp":                     "Jun 26 12:34:56",
				"host.name":                     "myhost",
				"SYSLOGPROG":                    "program",
				"system.auth.pam.module":        "pam_unix",
				"system.auth.pam.origin":        "sshd session",
				"system.auth.pam.session_state": "opened",
				"user.name":                     "john",
			},
		},
		{
			"CRON_ACTION",
			`%{CRON_ACTION}`,
			"CMD",
			map[string]string{
				"CRON_ACTION": "CMD",
			},
		},
		{
			"CRONLOG",
			`%{CRONLOG}`,
			"Jun 26 12:34:56 myhost CRON[12345]: (john) CMD (ls -la)",
			map[string]string{
				"timestamp":          "Jun 26 12:34:56",
				"host.name":          "myhost",
				"SYSLOGPROG":         "CRON[12345]",
				"user.name":          "john",
				"system.cron.action": "CMD",
				"message":            "ls -la",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Syslog)
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
				require.Equalf(t, v, val, "Values not equal for key %q. Expected %q, have %q", k, v, val)
			}
		})
	}
}
