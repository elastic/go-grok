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

package grok_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-grok"
)

func TestParseNoMatchReturnsEmptyMap(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`%{WORD:word} %{INT:number:int}`, true))

	for _, tt := range []struct {
		name  string
		check func(*testing.T)
	}{
		{"ParseString", func(t *testing.T) {
			captures, err := g.ParseString("1234")
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"Parse", func(t *testing.T) {
			captures, err := g.Parse([]byte("1234"))
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"ParseTypedString", func(t *testing.T) {
			captures, err := g.ParseTypedString("1234")
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"ParseTyped", func(t *testing.T) {
			captures, err := g.ParseTyped([]byte("1234"))
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

func TestByteAndStringAPIsHaveMatchingResults(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`%{WORD:word} %{INT:number:int}`, true))

	text := "hello 42"

	require.Equal(t, g.MatchString(text), g.Match([]byte(text)))

	stringCaptures, err := g.ParseString(text)
	require.NoError(t, err)

	byteCaptures, err := g.Parse([]byte(text))
	require.NoError(t, err)
	require.Len(t, byteCaptures, len(stringCaptures))
	for name, value := range stringCaptures {
		require.Equal(t, value, string(byteCaptures[name]))
	}

	typedStringCaptures, err := g.ParseTypedString(text)
	require.NoError(t, err)

	typedByteCaptures, err := g.ParseTyped([]byte(text))
	require.NoError(t, err)
	require.Equal(t, typedStringCaptures, typedByteCaptures)
}

func TestParseByteCapturesDoNotAliasInput(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`%{WORD:word} %{INT:number}`, true))

	text := []byte("hello 42")
	captures, err := g.Parse(text)
	require.NoError(t, err)

	text[0] = 'j'
	text[len(text)-1] = '0'

	require.Equal(t, []byte("hello"), captures["word"])
	require.Equal(t, []byte("42"), captures["number"])
}

func TestParseByteCapturesAreIndependent(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`%{WORD:first} %{WORD:second}`, true))

	captures, err := g.Parse([]byte("hello world"))
	require.NoError(t, err)

	captures["first"][0] = 'j'
	require.Equal(t, []byte("jello"), captures["first"])
	require.Equal(t, []byte("world"), captures["second"])

	extended := append(captures["first"], '!')
	require.Equal(t, []byte("jello!"), extended)
	require.Equal(t, []byte("world"), captures["second"])
}

func TestParseWithoutCaptureGroupsReturnsEmptyMap(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`foo`, true))

	for _, tt := range []struct {
		name  string
		check func(*testing.T, string)
	}{
		{"ParseString", func(t *testing.T, text string) {
			captures, err := g.ParseString(text)
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"Parse", func(t *testing.T, text string) {
			captures, err := g.Parse([]byte(text))
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"ParseTypedString", func(t *testing.T, text string) {
			captures, err := g.ParseTypedString(text)
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
		{"ParseTyped", func(t *testing.T, text string) {
			captures, err := g.ParseTyped([]byte(text))
			require.NoError(t, err)
			require.NotNil(t, captures)
			require.Empty(t, captures)
		}},
	} {
		t.Run(tt.name+"/match", func(t *testing.T) {
			tt.check(t, "food")
		})

		t.Run(tt.name+"/no_match", func(t *testing.T) {
			tt.check(t, "bar")
		})
	}
}

func TestParseTypedInvalidTypeHintReturnsTypeError(t *testing.T) {
	g := grok.New()
	require.NoError(t, g.Compile(`%{WORD:word:nope}`, true))

	captures, err := g.ParseTypedString("hello")
	require.ErrorIs(t, err, grok.ErrTypeNotProvided)
	require.Nil(t, captures)
}

func TestCompileExpansionSemantics(t *testing.T) {
	tests := []struct {
		name              string
		patterns          map[string]string
		pattern           string
		text              string
		namedCapturesOnly bool
		want              map[string]string
	}{
		{
			name:              "repeated tokens keep distinct targets",
			pattern:           `%{WORD:first} %{WORD:second}`,
			text:              "hello world",
			namedCapturesOnly: true,
			want: map[string]string{
				"first":  "hello",
				"second": "world",
			},
		},
		{
			name: "nested expansion keeps inner captures",
			patterns: map[string]string{
				"OUTER": `%{INNER} %{WORD:second}`,
				"INNER": `%{WORD:first}`,
			},
			pattern:           `%{OUTER}`,
			text:              "hello world",
			namedCapturesOnly: true,
			want: map[string]string{
				"first":  "hello",
				"second": "world",
			},
		},
		{
			name:              "dotted fields are restored in output names",
			pattern:           `%{WORD:destination.port}`,
			text:              "hello",
			namedCapturesOnly: true,
			want: map[string]string{
				"destination.port": "hello",
			},
		},
		{
			name:              "unnamed captures are skipped when named only",
			pattern:           `%{WORD}`,
			text:              "hello",
			namedCapturesOnly: true,
			want:              map[string]string{},
		},
		{
			name:              "unnamed captures use pattern name when allowed",
			pattern:           `%{WORD}`,
			text:              "hello",
			namedCapturesOnly: false,
			want: map[string]string{
				"WORD": "hello",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := grok.New()
			require.NoError(t, g.AddPatterns(tt.patterns))
			require.NoError(t, g.Compile(tt.pattern, tt.namedCapturesOnly))

			got, err := g.ParseString(tt.text)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
