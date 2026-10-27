// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"slices"
	"testing"
)

func TestFindHTMLLinks(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			"specification example",
			`<!doctype html><html><head>
			<link rel="ai-catalog" href="/catalog/ai.json"
			      type="application/ai-catalog+json">
			</head><body></body></html>`,
			[]string{"/catalog/ai.json"},
		},
		{"upper case, unquoted", `<LINK REL=AI-CATALOG HREF=/c.json>`, []string{catalogPath}},
		{"single quotes, self-closing", `<link href='/c.json' rel='ai-catalog' />`, []string{catalogPath}},
		{"several relation types", `<link rel="alternate ai-catalog" href="/c.json">`, []string{catalogPath}},
		{
			"other relations and links without href",
			`<link rel="stylesheet" href="/a.css"><link rel="ai-catalogue" href="/x"><link rel="ai-catalog"><link rel="ai-catalog" href="">`,
			nil,
		},
		{
			"document order and entities",
			`<link rel="ai-catalog" href="/a?x=1&amp;y=2"><link rel="ai-catalog" href="/b?x=1&#38;y=&#x32;">`,
			[]string{"/a?x=1&y=2", "/b?x=1&y=2"},
		},
		{
			"comments and raw text",
			`<!-- <link rel="ai-catalog" href="/commented"> -->
			<script>document.write('<link rel="ai-catalog" href="/script">')</script>
			<style>/* <link rel="ai-catalog" href="/style"> */</style>
			<title><link rel="ai-catalog" href="/title"></title>
			<link rel="ai-catalog" href="/real">`,
			[]string{"/real"},
		},
		{"greater-than sign in a value", `<meta content="a > b"><link rel="ai-catalog" href="/c.json">`, []string{catalogPath}},
		{
			"stops at the end of the head",
			`<head><link rel="ai-catalog" href="/head"></head><body><link rel="ai-catalog" href="/body"></body>`,
			[]string{"/head"},
		},
		{"stops at the body", `<body><link rel="ai-catalog" href="/body">`, nil},
		{"first attribute wins", `<link rel="ai-catalog" href="/first" href="/second">`, []string{"/first"}},
		{"malformed", "<<<>>><link rel=\"ai-catalog", nil},
		{"empty", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findHTMLLinks([]byte(tt.html), LinkRelation).hrefs
			if !slices.Equal(got, tt.want) {
				t.Errorf("hrefs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindHTMLLinksBase(t *testing.T) {
	links := findHTMLLinks([]byte(`<base href="https://cdn.example/x/"><base href="/ignored"><link rel="ai-catalog" href="c.json">`), LinkRelation)

	if links.base != "https://cdn.example/x/" {
		t.Errorf("base = %q", links.base)
	}

	if !slices.Equal(links.hrefs, []string{"c.json"}) {
		t.Errorf("hrefs = %q", links.hrefs)
	}
}
