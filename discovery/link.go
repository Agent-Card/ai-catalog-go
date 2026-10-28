// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"slices"
	"strings"
)

// link is one link of a Link header (RFC 8288) that has a rel parameter.
type link struct {
	target string
	// rel holds the space-separated relation types, lowercased.
	rel []string
}

type linkParam struct {
	name  string
	value string
}

// targetsWithRel returns the targets of the links in headers that have the
// relation type rel, in order. Links with an anchor parameter describe another
// resource than the one that was requested and are skipped.
func targetsWithRel(headers []string, rel string) []string {
	var targets []string

	for _, header := range headers {
		for _, l := range parseLinkHeader(header) {
			if slices.Contains(l.rel, rel) {
				targets = append(targets, l.target)
			}
		}
	}

	return targets
}

// parseLinkHeader parses one Link header field value. Malformed links are
// skipped, not reported.
func parseLinkHeader(value string) []link {
	var links []link

	rest := value

	for {
		rest = strings.TrimLeft(rest, " \t,")

		after, ok := strings.CutPrefix(rest, "<")
		if !ok {
			// Junk between links: resume at the next comma, if any.
			i := strings.IndexByte(rest, ',')
			if i < 0 {
				break
			}

			rest = rest[i:]

			continue
		}

		target, afterTarget, ok := strings.Cut(after, ">")
		if !ok {
			break
		}

		var params []linkParam

		params, rest = parseLinkParams(afterTarget)

		if l, ok := newLink(strings.TrimSpace(target), params); ok {
			links = append(links, l)
		}
	}

	return links
}

func newLink(target string, params []linkParam) (link, bool) {
	var (
		rel      string
		haveRel  bool
		anchored bool
	)

	for _, p := range params {
		switch p.name {
		case "rel":
			// Only the first rel counts.
			if !haveRel {
				rel, haveRel = p.value, true
			}
		case "anchor":
			anchored = true
		}
	}

	if !haveRel || anchored {
		return link{}, false
	}

	l := link{target: target}
	for r := range strings.FieldsSeq(rel) {
		l.rel = append(l.rel, strings.ToLower(r))
	}

	return l, true
}

// parseLinkParams parses "; name=value" parameters up to the next
// link-separating comma. It returns the parameters and the unparsed rest,
// which starts at that comma.
func parseLinkParams(rest string) ([]linkParam, string) {
	var params []linkParam

	for {
		rest = strings.TrimLeft(rest, " \t")

		after, ok := strings.CutPrefix(rest, ";")
		if !ok {
			// Anything but a comma here is junk; skip to the next link.
			if i := strings.IndexByte(rest, ','); i >= 0 {
				return params, rest[i:]
			}

			return params, ""
		}

		rest = strings.TrimLeft(after, " \t")

		nameEnd := strings.IndexFunc(rest, func(r rune) bool {
			return r == '=' || r == ';' || r == ',' || r == ' ' || r == '\t'
		})
		if nameEnd < 0 {
			nameEnd = len(rest)
		}

		name := strings.ToLower(rest[:nameEnd])
		rest = strings.TrimLeft(rest[nameEnd:], " \t")

		var value string

		if afterEq, ok := strings.CutPrefix(rest, "="); ok {
			value, rest = parseLinkValue(strings.TrimLeft(afterEq, " \t"))
		}

		if name != "" {
			params = append(params, linkParam{name: name, value: value})
		}
	}
}

// parseLinkValue reads a token or a quoted string and returns it with the
// unparsed rest.
func parseLinkValue(input string) (string, string) {
	quoted, ok := strings.CutPrefix(input, `"`)
	if !ok {
		end := strings.IndexAny(input, "; \t,")
		if end < 0 {
			end = len(input)
		}

		return input[:end], input[end:]
	}

	var value strings.Builder

	for i := 0; i < len(quoted); i++ {
		switch quoted[i] {
		case '"':
			return value.String(), quoted[i+1:]
		case '\\':
			i++
			if i < len(quoted) {
				value.WriteByte(quoted[i])
			}
		default:
			value.WriteByte(quoted[i])
		}
	}

	return value.String(), ""
}
