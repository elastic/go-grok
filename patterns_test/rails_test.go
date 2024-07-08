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

func TestParseWithPatterns_Rails(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"RUUID",
			"%{RUUID}",
			"e7df6a1e8414e16c36d76a9e52c4c72f",
			map[string]string{
				"RUUID": "e7df6a1e8414e16c36d76a9e52c4c72f",
			},
		},
		{
			"RCONTROLLER",
			"%{RCONTROLLER}",
			"UsersController#show",
			map[string]string{
				"rails.controller.class":  "UsersController",
				"rails.controller.action": "show",
			},
		},
		{
			"RAILS3HEAD",
			"%{RAILS3HEAD}",
			"Started GET \"/users/123\" for 127.0.0.1 at 2024-06-26 12:34:56 -0700",
			map[string]string{
				"http.request.method": "GET",
				"url.original":        "/users/123",
				"source.address":      "127.0.0.1",
				"timestamp":           "2024-06-26 12:34:56 -0700",
			},
		},
		{
			"RPROCESSING",
			"%{RPROCESSING}",
			"Processing by UsersController#show as HTML Parameters: {\"id\"=>\"123\"}",
			map[string]string{
				"rails.controller.class":  "UsersController",
				"rails.controller.action": "show",
				"rails.request.format":    "HTML",
				"rails.request.params":    "\"id\"=>\"123\"",
			},
		},
		{
			"RAILS3FOOT",
			"%{RAILS3FOOT}",
			"Completed 200 OK in 50ms (Views: 20ms | ActiveRecord: 10ms)",
			map[string]string{
				"http.response.status_code":            "200",
				"rails.request.duration.total":         "50",
				"rails.request.duration.view":          "20",
				"rails.request.duration.active_record": "10",
			},
		},
		{
			"RAILS3PROFILE",
			"%{RAILS3PROFILE}",
			"(Views: 20ms | ActiveRecord: 10ms)",
			map[string]string{
				"rails.request.duration.view":          "20",
				"rails.request.duration.active_record": "10",
			},
		},
		{
			"RAILS3",
			"%{RAILS3}",
			"Started GET \"/users/123\" for 127.0.0.1 at 2024-06-26 12:34:56 -0700 Processing by UsersController#show as HTML Parameters: {\"id\"=>\"123\"} Completed 200 OK in 50ms (Views: 20ms | ActiveRecord: 10ms)",
			map[string]string{
				"http.request.method":                  "GET",
				"url.original":                         "/users/123",
				"source.address":                       "127.0.0.1",
				"timestamp":                            "2024-06-26 12:34:56 -0700",
				"rails.controller.class":               "UsersController",
				"rails.controller.action":              "show",
				"rails.request.format":                 "HTML",
				"rails.request.params":                 "\"id\"=>\"123\"",
				"http.response.status_code":            "200",
				"rails.request.duration.total":         "50",
				"rails.request.duration.view":          "20",
				"rails.request.duration.active_record": "10",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Rails)
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
