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

func TestParseWithPatterns_MongoDB(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"MONGO_LOG",
			"%{MONGO_LOG}",
			"Jun 26 12:34:56 [NETWORK] Connection accepted",
			map[string]string{
				"timestamp":         "Jun 26 12:34:56",
				"mongodb.component": "NETWORK",
				"message":           "Connection accepted",
			},
		},
		{
			"MONGO_QUERY",
			"%{MONGO_QUERY}",
			"{ this is the content to capture } ntoreturn: some additional text",
			map[string]string{
				"MONGO_QUERY": "this is the content to capture",
			},
		},
		{
			"MONGO_SLOWQUERY",
			"%{MONGO_SLOWQUERY}",
			"find testdb.users query: { find: \"users\", filter: { age: { $gt: 30 } } } ntoreturn:1 ntoskip:0 nscanned:1000 nreturned:1 123ms",
			map[string]string{
				"mongodb.profile.op":        "find",
				"mongodb.database":          "testdb",
				"mongodb.collection":        "users",
				"mongodb.query.original":    "find: \"users\", filter: { age: { $gt: 30 } }",
				"mongodb.profile.ntoreturn": "1",
				"mongodb.profile.ntoskip":   "0",
				"mongodb.profile.nscanned":  "1000",
				"mongodb.profile.nreturned": "1",
				"mongodb.profile.duration":  "123",
			},
		},
		{
			"MONGO_WORDDASH",
			"%{MONGO_WORDDASH}",
			"testdb-users",
			map[string]string{
				"MONGO_WORDDASH": "testdb-users",
			},
		},
		{
			"MONGO3_SEVERITY",
			"%{MONGO3_SEVERITY}",
			"I",
			map[string]string{
				"MONGO3_SEVERITY": "I",
			},
		},
		{
			"MONGO3_COMPONENT",
			"%{MONGO3_COMPONENT}",
			"NETWORK",
			map[string]string{
				"MONGO3_COMPONENT": "NETWORK",
			},
		},
		{
			"MONGO3_LOG",
			"%{MONGO3_LOG}",
			"2024-06-26T12:34:56Z I NETWORK [conn1] connection accepted",
			map[string]string{
				"timestamp":         "2024-06-26T12:34:56Z",
				"log.level":         "I",
				"mongodb.component": "NETWORK",
				"mongodb.context":   "conn1",
				"message":           "connection accepted",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.MongoDB)
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
