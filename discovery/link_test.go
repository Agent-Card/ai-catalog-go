// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"slices"
	"testing"
)

const catalogPath = "/c.json"

func TestTargetsWithRel(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    []string
	}{
		{"specification example", []string{`<https://example.com/catalog/ai.json>; rel="ai-catalog"`}, []string{"https://example.com/catalog/ai.json"}},
		{"bare token, any case", []string{`</c.json>; REL=ai-catalog`}, []string{catalogPath}},
		{
			"picks the match out of several",
			[]string{`</style.css>; rel=preload; as=style, <https://a.example/ai.json>; rel="ai-catalog"; type="application/ai-catalog+json", </next>; rel=next`},
			[]string{"https://a.example/ai.json"},
		},
		{"one of several relation types", []string{`</c.json>; rel="alternate ai-catalog"`}, []string{catalogPath}},
		{"a longer relation type", []string{`</c.json>; rel="ai-catalogs"`}, nil},
		{"commas and semicolons in quotes", []string{`</a?x=1,2>; title="a, b; c"; rel="ai-catalog"`}, []string{"/a?x=1,2"}},
		{"only the first rel counts", []string{`</a>; rel=next; rel="ai-catalog"`}, nil},
		{"anchor", []string{`</a>; rel="ai-catalog"; anchor="#frag"`}, nil},
		{"unterminated target", []string{"<unterminated; rel=ai-catalog"}, nil},
		{"rel without value", []string{"</a>; rel"}, nil},
		{"junk before a link", []string{"junk, </b>; rel=ai-catalog"}, []string{"/b"}},
		{"junk after a target", []string{"</a> junk, </b>; rel=ai-catalog"}, []string{"/b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetsWithRel(tt.headers, LinkRelation)
			if !slices.Equal(got, tt.want) {
				t.Errorf("targetsWithRel(%q) = %q, want %q", tt.headers, got, tt.want)
			}
		})
	}
}
