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

func TestParseWithPatterns_Exim(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"EXIM_MSGID",
			"%{EXIM_MSGID}",
			"abc123-def456-gh",
			map[string]string{
				"EXIM_MSGID": "abc123-def456-gh",
			},
		},
		{
			"EXIM_FLAGS",
			"%{EXIM_FLAGS}",
			"->",
			map[string]string{
				"EXIM_FLAGS": "->",
			},
		},
		{
			"EXIM_DATE",
			"%{EXIM_DATE}",
			"2024-06-18 12:34:56",
			map[string]string{
				"YEAR":     "2024",
				"MONTHNUM": "06",
				"MONTHDAY": "18",
				"TIME":     "12:34:56",
			},
		},
		{
			"EXIM_PID",
			"%{EXIM_PID}",
			"[12345]",
			map[string]string{
				"process.pid": "12345",
			},
		},
		{
			"EXIM_QT",
			"%{EXIM_QT}",
			"1y2w3d4h5m6s",
			map[string]string{
				"EXIM_QT": "1y2w3d4h5m6s",
			},
		},
		{
			"EXIM_EXCLUDE_TERMS",
			"%{EXIM_EXCLUDE_TERMS}",
			"Message is frozen",
			map[string]string{
				"EXIM_EXCLUDE_TERMS": "Message is frozen",
			},
		},
		{
			"EXIM_REMOTE_HOST",
			"%{EXIM_REMOTE_HOST}",
			"H=(mail.example.com) (192.168.1.1) [192.168.1.1]:25",
			map[string]string{
				"source.address":          "mail.example.com",
				"exim.log.remote_address": "192.168.1.1",
				"source.ip":               "192.168.1.1",
				"source.port":             "25",
			},
		},
		{
			"EXIM_INTERFACE",
			"%{EXIM_INTERFACE}",
			"I=[192.168.1.1]:25",
			map[string]string{
				"destination.ip":   "192.168.1.1",
				"destination.port": "25",
			},
		},
		{
			"EXIM_PROTOCOL",
			"%{EXIM_PROTOCOL}",
			"P=SMTP",
			map[string]string{
				"network.protocol": "SMTP",
			},
		},
		{
			"EXIM_MSG_SIZE",
			"%{EXIM_MSG_SIZE}",
			"S=1024",
			map[string]string{
				"exim.log.message.size": "1024",
			},
		},
		{
			"EXIM_HEADER_ID",
			"%{EXIM_HEADER_ID}",
			"id=ABC123",
			map[string]string{
				"exim.log.header_id": "ABC123",
			},
		},
		{
			"EXIM_QUOTED_CONTENT",
			"%{EXIM_QUOTED_CONTENT}",
			"quoted\"",
			map[string]string{
				"EXIM_QUOTED_CONTENT": "quoted",
			},
		},
		{
			"EXIM_SUBJECT",
			"%{EXIM_SUBJECT}",
			`T="Important Email Subject"`,
			map[string]string{
				"exim.log.message.subject": "Important Email Subject",
			},
		},
		{
			"EXIM_UNKNOWN_FIELD",
			"%{EXIM_UNKNOWN_FIELD}",
			`abcd="value1"`,
			map[string]string{
				"EXIM_UNKNOWN_FIELD": `abcd="value1"`,
			},
		},
		{
			"EXIM_NAMED_FIELDS",
			"%{EXIM_NAMED_FIELDS}",
			" H=(mail.example.com) (192.168.1.1) [192.168.1.1]:25 I=[192.168.1.1]:25",
			map[string]string{
				"source.address":          "mail.example.com",
				"exim.log.remote_address": "192.168.1.1",
				"source.ip":               "192.168.1.1",
				"source.port":             "25",

				"destination.ip":   "192.168.1.1",
				"destination.port": "25",
			},
		},
		{
			"EXIM_MESSAGE_ARRIVAL",
			"%{EXIM_MESSAGE_ARRIVAL}",
			"2024-06-18 12:34:56 [1234] 123456-ABCDEF-78 <= sender@example.com H=(mail.example.com) (192.168.1.1) [192.168.1.1]:25 I=[192.168.1.1]:25 from <original_sender@example.com> for recipient@example.com",
			map[string]string{
				"timestamp":                "2024-06-18 12:34:56",
				"process.pid":              "1234",
				"exim.log.message.id":      "123456-ABCDEF-78",
				"exim.log.flags":           "<=",
				"exim.log.sender.email":    "sender@example.com",
				"exim.log.sender.original": "original_sender@example.com",
				"exim.log.recipient.email": "recipient@example.com",

				// named fields
				"source.address":          "mail.example.com",
				"exim.log.remote_address": "192.168.1.1",
				"source.ip":               "192.168.1.1",
				"source.port":             "25",

				"destination.ip":   "192.168.1.1",
				"destination.port": "25",
			},
		}, {
			"EXIM",
			"%{EXIM}",
			"2024-06-18 12:34:56 [1234] 123456-ABCDEF-78 <= sender@example.com H=(mail.example.com) (192.168.1.1) [192.168.1.1]:25 I=[192.168.1.1]:25 from <original_sender@example.com> for recipient@example.com",
			map[string]string{
				"timestamp":                "2024-06-18 12:34:56",
				"process.pid":              "1234",
				"exim.log.message.id":      "123456-ABCDEF-78",
				"exim.log.flags":           "<=",
				"exim.log.sender.email":    "sender@example.com",
				"exim.log.sender.original": "original_sender@example.com",
				"exim.log.recipient.email": "recipient@example.com",

				// named fields
				"source.address":          "mail.example.com",
				"exim.log.remote_address": "192.168.1.1",
				"source.ip":               "192.168.1.1",
				"source.port":             "25",

				"destination.ip":   "192.168.1.1",
				"destination.port": "25",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Exim)
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
