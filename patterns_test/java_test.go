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

func TestParseWithPatterns_Java(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"JAVACLASS",
			"%{JAVACLASS}",
			"com.example.ClassName",
			map[string]string{
				"JAVACLASS": "com.example.ClassName",
			},
		},
		{
			"JAVAFILE",
			"%{JAVAFILE}",
			"Example.java",
			map[string]string{
				"JAVAFILE": "Example.java",
			},
		},
		{
			"JAVAMETHOD",
			"%{JAVAMETHOD}",
			"methodName",
			map[string]string{
				"JAVAMETHOD": "methodName",
			},
		},
		{
			"JAVASTACKTRACEPART",
			"%{JAVASTACKTRACEPART}",
			"    at com.example.ClassName.methodName(Example.java:123)",
			map[string]string{
				"java.log.origin.class.name": "com.example.ClassName",
				"log.origin.function":        "methodName",
				"log.origin.file.name":       "Example.java",
				"log.origin.file.line":       "123",
			},
		},
		{
			"JAVATHREAD",
			"%{JAVATHREAD}",
			"AB-Processor123",
			map[string]string{
				"JAVATHREAD": "AB-Processor123",
			},
		},
		{
			"JAVALOGMESSAGE",
			"%{JAVALOGMESSAGE}",
			"This is a log message",
			map[string]string{
				"JAVALOGMESSAGE": "This is a log message",
			},
		},
		{
			"CATALINA7_DATESTAMP",
			"%{CATALINA7_DATESTAMP}",
			"Jun 26, 2024 12:34:56 PM",
			map[string]string{
				"CATALINA7_DATESTAMP": "Jun 26, 2024 12:34:56 PM",
			},
		},
		{
			"CATALINA7_LOG",
			"%{CATALINA7_LOG}",
			"Jun 26, 2024 12:34:56 PM org.example.MyClass myMethod INFO: This is a log message",
			map[string]string{
				"timestamp":                  "Jun 26, 2024 12:34:56 PM",
				"java.log.origin.class.name": "org.example.MyClass",
				"log.origin.function":        "myMethod",
				"log.level":                  "INFO",
				"message":                    "This is a log message",
			},
		},
		{
			"CATALINA8_DATESTAMP",
			"%{CATALINA8_DATESTAMP}",
			"26-Jun-2024 12:34:56",
			map[string]string{
				"CATALINA8_DATESTAMP": "26-Jun-2024 12:34:56",
			},
		},
		{
			"CATALINA8_LOG",
			"%{CATALINA8_LOG}",
			"26-Jun-2024 12:34:56 INFO [main] org.example.MyClass.myMethod This is a log message",
			map[string]string{
				"timestamp":                   "26-Jun-2024 12:34:56",
				"log.level":                   "INFO",
				"java.log.origin.thread.name": "main",
				"java.log.origin.class.name":  "org.example.MyClass",
				"log.origin.function":         "myMethod",
				"message":                     "This is a log message",
			},
		},
		{
			"CATALINA_DATESTAMP",
			"%{CATALINA_DATESTAMP}",
			"26-Jun-2024 12:34:56",
			map[string]string{
				"CATALINA_DATESTAMP": "26-Jun-2024 12:34:56",
			},
		},
		{
			"CATALINALOG",
			"%{CATALINALOG}",
			"26-Jun-2024 12:34:56 INFO [main] org.example.MyClass.myMethod This is a log message",
			map[string]string{
				"timestamp":                   "26-Jun-2024 12:34:56",
				"log.level":                   "INFO",
				"java.log.origin.thread.name": "main",
				"java.log.origin.class.name":  "org.example.MyClass",
				"log.origin.function":         "myMethod",
				"message":                     "This is a log message",
			},
		},
		{
			"TOMCAT7_LOG",
			`%{TOMCAT7_LOG}`,
			"Jun 26, 2024 12:34:56 PM org.example.MyClass myMethod INFO: This is a log message",
			map[string]string{
				"timestamp":                  "Jun 26, 2024 12:34:56 PM",
				"java.log.origin.class.name": "org.example.MyClass",
				"log.origin.function":        "myMethod",
				"log.level":                  "INFO",
				"message":                    "This is a log message",
			},
		},
		{
			"TOMCAT8_LOG",
			`%{TOMCAT8_LOG}`,
			"26-Jun-2024 12:34:56 INFO [main] org.example.MyClass.myMethod This is a log message",
			map[string]string{
				"timestamp":                   "26-Jun-2024 12:34:56",
				"log.level":                   "INFO",
				"java.log.origin.thread.name": "main",
				"java.log.origin.class.name":  "org.example.MyClass",
				"log.origin.function":         "myMethod",
				"message":                     "This is a log message",
			},
		},
		{
			"TOMCATLEGACY_DATESTAMP",
			`%{TOMCATLEGACY_DATESTAMP}`,
			"2024-06-26 12:34:56",
			map[string]string{
				"TOMCATLEGACY_DATESTAMP": "2024-06-26 12:34:56",
			},
		},
		{
			"TOMCATLEGACY_LOG",
			`%{TOMCATLEGACY_LOG}`,
			"2024-06-26 12:34:56 | INFO | org.example.MyClass - This is a legacy log message",
			map[string]string{
				"timestamp":                  "2024-06-26 12:34:56",
				"log.level":                  "INFO",
				"java.log.origin.class.name": "org.example.MyClass",
				"message":                    "This is a legacy log message",
			},
		},
		{
			"TOMCAT_DATESTAMP",
			`%{TOMCAT_DATESTAMP}`,
			"2024-06-26 12:34:56",
			map[string]string{
				"TOMCAT_DATESTAMP": "2024-06-26 12:34:56",
			},
		},
		{
			"TOMCATLOG - 7",
			`%{TOMCATLOG}`,
			"Jun 26, 2024 12:34:56 PM org.example.MyClass myMethod INFO: This is a log message",
			map[string]string{
				"timestamp":                  "Jun 26, 2024 12:34:56 PM",
				"java.log.origin.class.name": "org.example.MyClass",
				"log.origin.function":        "myMethod",
				"log.level":                  "INFO",
				"message":                    "This is a log message",
			},
		},

		{
			"TOMCATLOG - 8",
			`%{TOMCATLOG}`,
			"26-Jun-2024 12:34:56 INFO [main] org.example.MyClass.myMethod This is a log message",
			map[string]string{
				"timestamp":                   "26-Jun-2024 12:34:56",
				"log.level":                   "INFO",
				"java.log.origin.thread.name": "main",
				"java.log.origin.class.name":  "org.example.MyClass",
				"log.origin.function":         "myMethod",
				"message":                     "This is a log message",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.Java)
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
