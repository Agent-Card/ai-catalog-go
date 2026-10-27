// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// htmlLinks holds what discovery reads from the head of an HTML document.
type htmlLinks struct {
	// base is the href of the first base element.
	base string
	// hrefs are the hrefs of the link elements with the wanted relation type,
	// in document order.
	hrefs []string
}

// findHTMLLinks returns the href of every link element with the relation type
// rel, and the href of the first base element, up to the end of the document
// head. Markup inside comments, scripts and other raw-text elements is not
// seen, because the tokenizer does not treat it as markup.
func findHTMLLinks(body []byte, rel string) htmlLinks {
	var links htmlLinks

	var haveBase bool

	z := html.NewTokenizer(bytes.NewReader(body))

	for {
		switch z.Next() {
		case html.ErrorToken:
			return links
		case html.TextToken, html.CommentToken, html.DoctypeToken:
			// Not markup that matters here.
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "head" {
				return links
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := readAttributes(z, hasAttr)

			switch string(name) {
			case "body":
				return links
			case "base":
				if href, ok := attrs["href"]; ok && !haveBase {
					links.base, haveBase = href, true
				}
			case "link":
				if href := strings.TrimSpace(attrs["href"]); href != "" && hasRel(attrs["rel"], rel) {
					links.hrefs = append(links.hrefs, href)
				}
			}
		}
	}
}

// readAttributes returns the attributes of the current tag, with lowercased
// names and decoded values. As in HTML, the first occurrence of an attribute
// wins.
func readAttributes(z *html.Tokenizer, hasAttr bool) map[string]string {
	attrs := make(map[string]string)

	for hasAttr {
		var key, value []byte

		key, value, hasAttr = z.TagAttr()
		if _, seen := attrs[string(key)]; !seen {
			attrs[string(key)] = string(value)
		}
	}

	return attrs
}

func hasRel(value, rel string) bool {
	for token := range strings.FieldsSeq(value) {
		if strings.EqualFold(token, rel) {
			return true
		}
	}

	return false
}
