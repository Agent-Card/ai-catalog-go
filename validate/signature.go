// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"fmt"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/jws"
)

// Protected header "typ" values, by the kind of object a signature is attached to.
const (
	catalogJWSType  = "ai-catalog+jws"
	manifestJWSType = "ai-catalog-trust-manifest+jws"
)

// instant parses an RFC 3339 timestamp.
func instant(value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, value)

	return t, err == nil
}

// validateSignature checks a signature object's structure and returns its
// protected header when the JWS is a well-formed detached compact serialization.
// Signatures are not verified.
func (v *validator) validateSignature(signature *catalog.Signature, typ, path string) (jws.Header, bool) {
	required := []struct{ member, value string }{
		{"signer", signature.Signer},
		{"profile", signature.Profile},
		{"issuedAt", signature.IssuedAt},
		{"jws", signature.JWS},
	}

	for _, r := range required {
		if r.value == "" {
			v.addError(CodeSignatureMember, path+"."+r.member,
				fmt.Sprintf("signature.%s is required and must not be empty", r.member))
		}
	}

	if signature.Signer != "" && !isAbsoluteURI(signature.Signer) {
		v.addError(CodeSignatureSigner, path+".signer", "signature.signer must be an absolute URI")
	}

	v.validateTimestamp(signature.IssuedAt, path+".issuedAt")
	v.validateValidityWindow(signature, path)

	return v.validateJWS(signature.JWS, typ, path+".jws")
}

func (v *validator) validateValidityWindow(signature *catalog.Signature, path string) {
	if signature.ExpiresAt == "" {
		return
	}

	v.validateTimestamp(signature.ExpiresAt, path+".expiresAt")

	issued, issuedOK := instant(signature.IssuedAt)
	expires, expiresOK := instant(signature.ExpiresAt)

	if issuedOK && expiresOK && !expires.After(issued) {
		v.addError(CodeSignatureExpiry, path+".expiresAt", "signature.expiresAt must be later than issuedAt")
	}
}

func (v *validator) validateJWS(signature, typ, path string) (jws.Header, bool) {
	if signature == "" {
		return jws.Header{}, false
	}

	if !jws.Detached(signature) {
		v.addError(CodeSignatureForm, path, "jws must use detached compact serialization")

		return jws.Header{}, false
	}

	header, err := jws.Parse(signature)
	if err != nil {
		v.addError(CodeSignatureMalformed, path,
			fmt.Sprintf("jws header must be base64url-encoded JSON declaring an 'alg': %v", err))

		return jws.Header{}, false
	}

	if jws.Forbidden(header.Algorithm) {
		v.addError(CodeSignatureAlgorithm, path, fmt.Sprintf("jws algorithm '%s' must be rejected", header.Algorithm))
	}

	if header.Has("b64") {
		v.addError(CodeSignatureB64, path, "jws header must not contain 'b64'")
	}

	if header.Type != typ {
		v.addError(CodeSignatureType, path, fmt.Sprintf("jws header typ must be %q, found %q", typ, header.Type))
	}

	return header, true
}

// signatureCurrent reports whether the signature may be accepted at the clock
// time: issued, and not expired. A signature outside that window is warned about.
func (v *validator) signatureCurrent(signature *catalog.Signature, path string) bool {
	current := true

	if issued, ok := instant(signature.IssuedAt); ok && issued.After(v.now) {
		current = false

		v.addWarning(CodeSignatureNotYetValid, path+".issuedAt", fmt.Sprintf(
			"signature issuedAt %q is in the future and MUST NOT be accepted yet", signature.IssuedAt))
	}

	if expires, ok := instant(signature.ExpiresAt); ok && !expires.After(v.now) {
		current = false

		v.addWarning(CodeSignatureExpired, path+".expiresAt", fmt.Sprintf(
			"signature expired at %q and MUST NOT be accepted", signature.ExpiresAt))
	}

	return current
}
