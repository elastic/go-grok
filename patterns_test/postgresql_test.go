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

func TestParseWithPatterns_PostgreSQL(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"POSTGRESQL",
			"%{POSTGRESQL}",
			"2024-06-18 12:34:56 UTC johndoe 12345 67890",
			map[string]string{
				"timestamp":                    "24-06-18 12:34:56",
				"event.timezone":               "UTC",
				"user.name":                    "johndoe",
				"postgresql.log.connection_id": "12345",
				"process.pid":                  "67890",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.PostgreSQL)
			require.NoError(t, err)
			require.NoError(t, g.Compile(tt.Pattern, true))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}
