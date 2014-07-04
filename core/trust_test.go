/*
 * Copyright (c) 2014 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package core

import (
	"github.com/marcopeereboom/mcrypt"
	"io/ioutil"
	"os"
	"testing"
)

var (
	tmpDir string
	trust  *Trust
	alice  *mcrypt.Identity
	bob    *mcrypt.Identity
)

func TestDbTempDir(t *testing.T) {
	var err error

	tmpDir, err = ioutil.TempDir(os.TempDir(), "trust")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestTrustOpen(t *testing.T) {
	var err error

	trust, err = NewTrust(tmpDir)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestTrustAdd(t *testing.T) {
	var err error

	alice, err = mcrypt.NewIdentity("Alice", "alice@localhost")
	if err != nil {
		t.Error(err)
		return
	}

	bob, err = mcrypt.NewIdentity("Bob", "bob@localhost")
	if err != nil {
		t.Error(err)
		return
	}

	// alice is trusting bob
	freeToUse := make(map[string]string)
	freeToUse["moo"] = "meh"
	err = trust.Add(alice, &bob.PublicIdentity, StateAllowed, freeToUse, false)
	if err != nil {
		t.Error(err)
		return
	}

	// alice is trusting bob
	err = trust.Add(alice, &bob.PublicIdentity, StateAllowed, nil, false)
	if err == nil {
		// should fail
		t.Error("dup should have tripped")
		return
	}

	tr, err := trust.Get(alice, &bob.PublicIdentity)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestTrustClose(t *testing.T) {
	trust.Close()
}
