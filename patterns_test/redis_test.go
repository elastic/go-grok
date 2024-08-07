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

func TestParseWithPatterns_Redis(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"REDISTIMESTAMP",
			`%{REDISTIMESTAMP}`,
			"26 Jun 12:34:56",
			map[string]string{
				"REDISTIMESTAMP": "26 Jun 12:34:56",
			},
		},
		{
			"REDISLOG",
			`%{REDISLOG}`,
			"[1234] 26 Jun 12:34:56 *",
			map[string]string{
				"process.pid": "1234",
				"timestamp":   "26 Jun 12:34:56",
			},
		},
		{
			"REDISMONLOG",
			`%{REDISMONLOG}`,
			"1624549200 [0 127.0.0.1:6379] \"GET\" \"mykey\"",
			map[string]string{
				"timestamp":          "1624549200",
				"redis.database.id":  "0",
				"client.address":     "127.0.0.1",
				"client.port":        "6379",
				"redis.command.name": "GET",
				"redis.command.args": "\"mykey\"",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.Redis)
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
