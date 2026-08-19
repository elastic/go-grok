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
	ErrUnsupportedName = fmt.Errorf("name contains unsupported character ':'")

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
	captureFields         []captureField
	lookupDefaultPatterns bool
}

type captureField struct {
	index     int
	name      string
	valueType captureValueType
}

type captureValueType uint8

const (
	captureValueString captureValueType = iota
	captureValueFloat
	captureValueInt
	captureValueBool
	captureValueInvalid
)

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

func NewWithPatterns(patterns ...map[string]string) (*Grok, error) {
	g := &Grok{
		patternDefinitions:    make(map[string]string),
		lookupDefaultPatterns: true,
	}

	for _, p := range patterns {
		if err := g.AddPatterns(p); err != nil {
			return nil, err
		}
	}

	return g, nil
}

// NewComplete creates a grok parser with full set of patterns
func NewComplete(additionalPatterns ...map[string]string) (*Grok, error) {
	g, err := NewWithPatterns(
		patterns.AWS,
		patterns.Bind9,
		patterns.Bro,
		patterns.Exim,
		patterns.HAProxy,
		patterns.Httpd,
		patterns.Firewalls,
		patterns.Java,
		patterns.Junos,
		patterns.Maven,
		patterns.MCollective,
		patterns.MongoDB,
		patterns.PostgreSQL,
		patterns.Rails,
		patterns.Redis,
		patterns.Ruby,
		patterns.Squid,
		patterns.Syslog,
	)
	if err != nil {
		return nil, err
	}

	for _, p := range additionalPatterns {
		if err := g.AddPatterns(p); err != nil {
			return nil, err
		}
	}

	return g, nil
}

func (grok *Grok) AddPattern(name, patternDefinition string) error {
	if strings.ContainsRune(name, ':') {
		return ErrUnsupportedName
	}

	// overwrite existing if present
	grok.patternDefinitions[name] = patternDefinition
	return nil
}

func (grok *Grok) AddPatterns(patternDefinitions map[string]string) error {
	// overwrite existing if present
	for name, patternDefinition := range patternDefinitions {
		if strings.ContainsRune(name, ':') {
			return ErrUnsupportedName
		}

		grok.patternDefinitions[name] = patternDefinition
	}
	return nil
}

func (grok *Grok) HasCaptureGroups() bool {
	if grok == nil || grok.re == nil {
		return false
	}
	return len(grok.captureFields) > 0
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
// When expression is not a match an empty map is returned.
func (grok *Grok) ParseString(text string) (map[string]string, error) {
	return grok.captureString(text)
}

// Parse parses text in a form of []byte and returns map[string][]byte with values
// not converted to types according to hints.
// When expression is not a match an empty map is returned.
func (grok *Grok) Parse(text []byte) (map[string][]byte, error) {
	return grok.captureBytes(text)
}

// ParseTyped parses text and returns map[string]any with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match an empty map is returned.
func (grok *Grok) ParseTyped(text []byte) (map[string]any, error) {
	return grok.captureTypedBytes(text)
}

// ParseTypedString parses text and returns map[string]any with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match an empty map is returned.
func (grok *Grok) ParseTypedString(text string) (map[string]any, error) {
	return grok.captureTyped(text)
}

func (grok *Grok) compile(pattern string, namedCapturesOnly bool) error {
	// get expanded pattern
	expandedExpression, hints, err := grok.expand(pattern, namedCapturesOnly)
	if err != nil {
		return err
	}

	if grok.re != nil && grok.re.String() == expandedExpression {
		grok.captureFields = buildCaptureFields(grok.re, hints)
		return nil
	}

	compiledExpression, err := regexp.Compile(expandedExpression)
	if err != nil {
		return err
	}

	grok.re = compiledExpression
	grok.captureFields = buildCaptureFields(compiledExpression, hints)

	return nil
}

func (grok *Grok) captureString(text string) (map[string]string, error) {
	fields := grok.captureFields
	if len(fields) == 0 {
		return make(map[string]string), nil
	}

	matches := grok.re.FindStringSubmatchIndex(text)
	if len(matches) == 0 {
		return make(map[string]string), nil
	}

	captures := make(map[string]string, len(fields))
	for _, field := range fields {
		start, end := matches[2*field.index], matches[2*field.index+1]
		if start < 0 || start == end {
			continue
		}

		captures[field.name] = text[start:end]
	}
	return captures, nil
}

func (grok *Grok) captureBytes(text []byte) (map[string][]byte, error) {
	return extractByteCaptures(grok.re, grok.captureFields, text)
}

func (grok *Grok) captureTyped(text string) (map[string]any, error) {
	fields := grok.captureFields
	if len(fields) == 0 {
		return make(map[string]any), nil
	}

	matches := grok.re.FindStringSubmatchIndex(text)
	if len(matches) == 0 {
		return make(map[string]any), nil
	}

	captures := make(map[string]any, len(fields))
	for _, field := range fields {
		start, end := matches[2*field.index], matches[2*field.index+1]
		if start < 0 || start == end {
			continue
		}

		v, err := grok.convertMatch(text[start:end], field)
		if err != nil {
			return nil, err
		}
		captures[field.name] = v
	}
	return captures, nil
}

func (grok *Grok) captureTypedBytes(text []byte) (map[string]any, error) {
	fields := grok.captureFields
	if len(fields) == 0 {
		return make(map[string]any), nil
	}

	matches := grok.re.FindSubmatchIndex(text)
	if len(matches) == 0 {
		return make(map[string]any), nil
	}

	captures := make(map[string]any, len(fields))
	for _, field := range fields {
		start, end := matches[2*field.index], matches[2*field.index+1]
		if start < 0 || start == end {
			continue
		}

		v, err := grok.convertMatch(string(text[start:end]), field)
		if err != nil {
			return nil, err
		}
		captures[field.name] = v
	}
	return captures, nil
}

func extractByteCaptures(re *regexp.Regexp, fields []captureField, text []byte) (map[string][]byte, error) {
	if len(fields) == 0 {
		return make(map[string][]byte), nil
	}

	matches := re.FindSubmatchIndex(text)
	if len(matches) == 0 {
		return make(map[string][]byte), nil
	}

	var totalBytes int
	for _, field := range fields {
		start, end := matches[2*field.index], matches[2*field.index+1]
		if start >= 0 && start != end {
			totalBytes += end - start
		}
	}

	buf := make([]byte, 0, totalBytes)
	captures := make(map[string][]byte, len(fields))
	for _, field := range fields {
		start, end := matches[2*field.index], matches[2*field.index+1]
		if start < 0 || start == end {
			continue
		}
		offset := len(buf)
		buf = append(buf, text[start:end]...)
		captures[field.name] = buf[offset:len(buf):len(buf)]
	}
	return captures, nil
}

func (grok *Grok) convertMatch(match string, field captureField) (any, error) {
	switch field.valueType {
	case captureValueString:
		return match, nil
	case captureValueFloat:
		return strconv.ParseFloat(match, 64)
	case captureValueInt:
		return strconv.Atoi(match)
	case captureValueBool:
		return strconv.ParseBool(match)
	default:
		return nil, fmt.Errorf("invalid type for %v: %w", strings.ReplaceAll(field.name, ".", dotSep), ErrTypeNotProvided)
	}
}

func buildCaptureFields(re *regexp.Regexp, hints map[string]string) []captureField {
	names := re.SubexpNames()
	fields := make([]captureField, 0, re.NumSubexp())
	for index, regexpName := range names {
		if regexpName == "" {
			continue
		}

		valueType := captureValueString
		if hint := hints[regexpName]; hint != "" {
			valueType = captureValueTypeForHint(hint)
		}
		fields = append(fields, captureField{
			index:     index,
			name:      strings.ReplaceAll(regexpName, dotSep, "."),
			valueType: valueType,
		})
	}
	return fields
}

func captureValueTypeForHint(hint string) captureValueType {
	switch hint {
	case "", "string":
		return captureValueString
	case "double", "float":
		return captureValueFloat
	case "int", "long":
		return captureValueInt
	case "bool", "boolean":
		return captureValueBool
	default:
		return captureValueInvalid
	}
}

// expand processes a pattern and returns expanded regular expression, type hints and error
func (grok *Grok) expand(pattern string, namedCapturesOnly bool) (string, map[string]string, error) {
	var hints map[string]string
	expandedPattern := pattern

	// recursion break is guarding against cyclic reference in pattern definitions
	// as this is performed only once at compile time more clever optimization (e.g detecting cycles in graph) is TBD
	for recursionBreak := 1000; recursionBreak > 0; recursionBreak-- {
		match := reusePattern.FindStringSubmatchIndex(expandedPattern)
		if match == nil {
			// nothing to expand anymore
			break
		}

		var b strings.Builder
		b.Grow(len(expandedPattern))
		var offset int

		for match != nil {
			// grok can be specified in either of these forms:
			// %{SYNTAX} - e.g {NUMBER}
			// %{SYNTAX:ID} - e.g {NUMBER:MY_AGE}
			// %{SYNTAX:ID:TYPE} - e.g {NUMBER:MY_AGE:INT}

			// match[2]:match[3] is the inner "SYNTAX:ID:TYPE" part.
			grokId, targetId, typeHint, hasTarget, hasType := parseGrokName(expandedPattern[offset+match[2] : offset+match[3]])

			knownPattern, found := grok.lookupPattern(grokId)
			if !found {
				return "", nil, fmt.Errorf("pattern definition %q unknown: %w", grokId, ErrParseFailure)
			}

			if hasType {
				if hints == nil {
					hints = make(map[string]string)
				}
				hints[targetId] = typeHint
			}

			b.WriteString(expandedPattern[offset : offset+match[0]])
			if namedCapturesOnly && !hasTarget {
				// this has no semantic (pattern:foo) so we don't need to capture;
				// a non-capturing group keeps the regexp engine from tracking it
				b.WriteString("(?:")
				b.WriteString(knownPattern)
				b.WriteByte(')')
			} else {
				b.WriteString("(?P<")
				b.WriteString(targetId)
				b.WriteByte('>')
				b.WriteString(knownPattern)
				b.WriteByte(')')
			}
			offset += match[1]
			match = reusePattern.FindStringSubmatchIndex(expandedPattern[offset:])
		}
		b.WriteString(expandedPattern[offset:])
		expandedPattern = b.String()
	}

	return expandedPattern, hints, nil
}

func parseGrokName(name string) (grokId, targetId, typeHint string, hasTarget, hasType bool) {
	grokId, rest, hasTarget := strings.Cut(name, ":")
	if !hasTarget {
		return grokId, grokId, "", false, false
	}

	target, typeHint, hasType := strings.Cut(rest, ":")
	return grokId, strings.ReplaceAll(target, ".", dotSep), typeHint, true, hasType
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
