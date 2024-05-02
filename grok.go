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

package grok

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/elastic/go-grok/patterns"
)

const dotSep = "___"

var (
	ErrParseFailure    = fmt.Errorf("parsing failed")
	ErrTypeNotProvided = fmt.Errorf("type not specified")

	// grok can be specified in either of these forms:
	// %{SYNTAX} - e.g {NUMBER}
	// %{SYNTAX:ID} - e.g {NUMBER:MY_AGE}
	// %{SYNTAX:ID:TYPE} - e.g {NUMBER:MY_AGE:INT}
	// supported types are int, long, double, float and boolean
	// for go specific implementation int and long results in int
	// double and float both results in float
	reusePattern = regexp.MustCompile(`%{(\w+(?::[\w+.]+(?::\w+)?)?)}`)
)

type Grok struct {
	patternDefinitions    map[string]string
	re                    *regexp.Regexp
	typeHints             map[string]string
	lookupDefaultPatterns bool
}

func New() *Grok {
	return &Grok{
		patternDefinitions:    make(map[string]string),
		lookupDefaultPatterns: true,
	}
}

func NewWithoutDefaultPatterns() *Grok {
	return &Grok{
		patternDefinitions: make(map[string]string),
	}
}

func (grok *Grok) AddPattern(name, patternDefinition string) {
	// overwrite existing if present
	grok.patternDefinitions[name] = patternDefinition
}

func (grok *Grok) AddPatterns(patternDefinitions map[string]string) {
	// overwrite existing if present
	for name, patternDefinition := range patternDefinitions {
		grok.patternDefinitions[name] = patternDefinition
	}
}

func (grok *Grok) Compile(pattern string, namedCapturesOnly bool) error {
	return grok.compile(pattern, namedCapturesOnly)
}

func (grok *Grok) Match(text []byte) bool {
	return grok.re.Match(text)
}

func (grok *Grok) MatchString(text string) bool {
	return grok.re.MatchString(text)
}

// ParseString parses text in a form of string and returns map[string]string with values
// not converted to types according to hints.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseString(text string) (map[string]string, error) {
	return grok.captureString(text)
}

// Parse parses text in a form of []byte and returns map[string][]byte with values
// not converted to types according to hints.
// When expression is not a match nil map is returned.
func (grok *Grok) Parse(text []byte) (map[string][]byte, error) {
	return grok.captureBytes(text)
}

// ParseTyped parses text and returns map[string]interface{} with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseTyped(text []byte) (map[string]interface{}, error) {
	captures, err := grok.captureTyped(text)
	if err != nil {
		return nil, err
	}

	captureBytes := make(map[string]interface{})
	for k, v := range captures {
		captureBytes[k] = v
	}

	return captureBytes, nil
}

// ParseTyped parses text and returns map[string]interface{} with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseTypedString(text string) (map[string]interface{}, error) {
	return grok.ParseTyped([]byte(text))
}

func (grok *Grok) compile(pattern string, namedCapturesOnly bool) error {
	// get expanded pattern
	expandedExpression, hints, err := grok.expand(pattern, namedCapturesOnly)
	if err != nil {
		return err
	}

	compiledExpression, err := regexp.Compile(expandedExpression)
	if err != nil {
		return err
	}

	grok.re = compiledExpression
	grok.typeHints = hints

	return nil
}

func (grok *Grok) captureString(text string) (map[string]string, error) {
	return captureTypeFn(grok.re, text,
		func(v, _ string) (string, error) {
			return v, nil
		},
	)
}

func (grok *Grok) captureBytes(text []byte) (map[string][]byte, error) {
	return captureTypeFn(grok.re, string(text),
		func(v, _ string) ([]byte, error) {
			return []byte(v), nil
		},
	)
}

func (grok *Grok) captureTyped(text []byte) (map[string]interface{}, error) {
	return captureTypeFn(grok.re, string(text), grok.convertMatch)
}

func captureTypeFn[K any](re *regexp.Regexp, text string, conversionFn func(v, key string) (K, error)) (map[string]K, error) {
	captures := make(map[string]K)

	matches := re.FindStringSubmatch(text)
	if len(matches) == 0 {
		return captures, nil
	}

	names := re.SubexpNames()
	if len(names) == 0 {
		return captures, nil
	}

	for i, name := range names {
		if len(name) == 0 {
			continue
		}

		match := matches[i]
		if len(match) == 0 {
			continue
		}

		if conversionFn != nil {
			v, err := conversionFn(string(match), name)
			if err != nil {
				return nil, err
			}
			captures[strings.ReplaceAll(name, dotSep, ".")] = v
		}
	}

	return captures, nil
}

func (grok *Grok) convertMatch(match, name string) (interface{}, error) {
	hint, found := grok.typeHints[name]
	if !found {
		return match, nil
	}

	switch hint {
	case "string":
		return match, nil

	case "double":
		strconv.ParseFloat(match, 64)
	case "float":
		strconv.ParseFloat(match, 64)

	case "int":
		return strconv.Atoi(match)
	case "long":
		return strconv.Atoi(match)

	case "bool":
		return strconv.ParseBool(match)
	case "boolean":
		return strconv.ParseBool(match)
	default:
		return nil, fmt.Errorf("invalid type for %v: %w", name, ErrTypeNotProvided)
	}

	return nil, nil
}

// expand processes a pattern and returns expanded regular expression, type hints and error
func (grok *Grok) expand(pattern string, namedCapturesOnly bool) (string, map[string]string, error) {
	hints := make(map[string]string)
	expandedPattern := pattern

	// recursion break is guarding against cyclic reference in pattern definitions
	// as this is performed only once at compile time more clever optimization (e.g detecting cycles in graph) is TBD
	for recursionBreak := 1000; recursionBreak > 0; recursionBreak-- {
		subMatches := reusePattern.FindAllStringSubmatch(expandedPattern, -1)
		if len(subMatches) == 0 {
			// nothing to expand anymore
			break
		}

		for _, nameSubmatch := range subMatches {
			// grok can be specified in either of these forms:
			// %{SYNTAX} - e.g {NUMBER}
			// %{SYNTAX:ID} - e.g {NUMBER:MY_AGE}
			// %{SYNTAX:ID:TYPE} - e.g {NUMBER:MY_AGE:INT}

			// nameSubmatch is equal to [["%{NAME:ID:TYPe}" "NAME:ID:TYPe"]]
			// we need only inner part
			nameParts := strings.Split(nameSubmatch[1], ":")

			grokId := nameParts[0]
			var targetId string
			if len(nameParts) > 1 {
				targetId = strings.ReplaceAll(nameParts[1], ".", dotSep)
			} else {
				targetId = nameParts[0]
			}
			// compile hints for used patterns
			if len(nameParts) == 3 {
				hints[targetId] = nameParts[2]
			}

			knownPattern, found := grok.lookupPattern(grokId)
			if !found {
				return "", nil, fmt.Errorf("pattern definition %q unknown: %w", grokId, ErrParseFailure)
			}

			var replacementPattern string
			if namedCapturesOnly && len(nameParts) == 1 {
				// this has no semantic (pattern:foo) so we don't need to capture
				replacementPattern = "(" + knownPattern + ")"

			} else {
				replacementPattern = "(?P<" + targetId + ">" + knownPattern + ")"
			}

			// expand pattern with definition
			expandedPattern = strings.ReplaceAll(expandedPattern, nameSubmatch[0], replacementPattern)
		}
	}

	return expandedPattern, hints, nil
}

func (grok *Grok) lookupPattern(grokId string) (string, bool) {
	if knownPattern, found := grok.patternDefinitions[grokId]; found {
		return knownPattern, found
	}

	if grok.lookupDefaultPatterns {
		if knownPattern, found := patterns.Default[grokId]; found {
			return knownPattern, found
		}
	}

	return "", false

}
