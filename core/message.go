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
)

// signal core to initiate shutdown
type Shutdown struct{}

// signal queueb loop to exit
type Exit struct{}

// signal core to send file
type SendFile struct {
	To       string
	Filename string
	Mime     string
}

// signal core that the UI is up and running
type UiReady struct{}

// signal UI to render a popup
type UiPopup struct {
	Title   string
	Message string
}

// signal UI to render identity
type UiRenderIdentity struct {
	PublicIdentity *mcrypt.PublicIdentity
}

// signal UI to render dialog to confirm identity
type UiConfirmIdentity struct {
	Message string
	Name    string
	Address string
}

// signal UI to render identity
type UiRenderTrust struct {
	TrustRecords []*TrustRecord
}

//signal core that the UI has obtained an identity
type UiConfirmIdentityReply struct {
	Name        string
	Address     string
	Identifiers []*mcrypt.Identifier
	Error       error
}

const (
	ProfilePicture = "ProfilePicture"
)

// signal UI to render dialog to confirm public identity
type UiConfirmPublicIdentity struct {
	PublicIdentity *mcrypt.PublicIdentity
}

//signal core that the UI has done something with the public identity
type UiConfirmPublicIdentityReply struct {
	PublicIdentity *mcrypt.PublicIdentity
	Error          error
	State          int
}

//signal core to update trust record
type UpdateTrustRecord struct {
	TrustRecord *TrustRecord
}
