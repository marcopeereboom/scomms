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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/marcopeereboom/mcrypt"
)

const (
	identityFilename = "/scomms.id"
	certFilename     = "/scomms.cert"
	keyFilename      = "/scomms.key"
)

func (c *Core) identityExists() bool {
	_, err := os.Stat(c.scommsDir + identityFilename)
	if err != nil {
		return false
	}
	return true
}

func (c *Core) identityOpen() error {
	s, err := ioutil.ReadFile(c.scommsDir + identityFilename)
	if err != nil {
		return err
	}
	c.identity, err = mcrypt.UnmarshalIdentity(s)
	if err != nil {
		return err
	}

	return nil
}

func (c *Core) identitySave() error {
	f, err := os.OpenFile(c.scommsDir+identityFilename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer f.Close()

	j, err := c.identity.Marshal()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "%s\n", j)
	if err != nil {
		return err
	}

	// generate cert
	// remove identifiers, they corrupt the cert
	pid := c.identity.PublicIdentity
	pid.Identifiers = nil
	jsonPid, err := pid.Marshal()
	if err != nil {
		return err
	}
	err = GenerateCert(c.scommsDir+certFilename,
		c.scommsDir+keyFilename,
		c.identity.PublicIdentity.Address,
		c.identity.PublicIdentity.Name,
		jsonPid)
	if err != nil {
		return err
	}

	return nil
}
