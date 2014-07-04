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

package main

import (
	"fmt"
	"os"

	"github.com/marcopeereboom/queueb"
	"github.com/marcopeereboom/scomms/core"
)

// handleIncoming decodes and handles incomming ui messages.
func (g *GtkContext) handleIncoming(msg *queueb.QueuebMessage) {
	switch m := msg.Message.(type) {
	case *core.UiRenderIdentity:
		g.RenderIdentity(m)
	case *core.UiConfirmIdentity:
		g.ConfirmIdentity(m)
	case *core.UiPopup:
		g.Popup(m)
	case *core.UiConfirmPublicIdentity:
		g.ConfirmPublicIdentity(m)
	case *core.UiRenderTrust:
		g.RenderTrust(m)
	default:
		g.DebugUi("unhandled message %T\n", msg.Message)
	}
}

func _main() error {
	c, err := core.New()
	if err != nil {
		return err
	}
	c.Start()

	// launch main window
	g, err := GtkInit(c)
	if err != nil {
		return err
	}

	// tell core we are ready to render
	err = c.SendCore(&core.UiReady{})
	if err != nil {
		return err
	}

	g.DebugUi("ready\n")
	for {
		m, err := c.ReceiveUi()
		if err != nil {
			return err
		}
		g.DebugUi("received %T\n", m.Message)
		switch m.Message.(type) {
		case *core.Exit:
			g.Exit()
			return nil
		default:
			g.handleIncoming(m)
		}
	}

	return nil
}

// main is the start of day of the application.
func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v")
		os.Exit(1)
	}
}
