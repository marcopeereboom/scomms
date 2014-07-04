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
	//"fmt"
	"github.com/conformal/gotk3/glib"
	"github.com/conformal/gotk3/gtk"
	"github.com/marcopeereboom/scomms/core"
)

func (g *GtkContext) addItem(lb *gtk.ListBox, key, val string) error {
	gr, err := gtk.GridNew()

	// key
	lblKey, err := gtk.LabelNew(key)
	if err != nil {
		g.DebugUi("addItem %v", err)
		return err
	}
	lblKey.SetHExpand(true)
	gr.Attach(lblKey, 0, 0, 1, 1)

	// val
	lblVal, err := gtk.LabelNew(val)
	if err != nil {
		g.DebugUi("addItem %v", err)
		return err
	}
	lblVal.SetHExpand(true)
	gr.Attach(lblVal, 1, 0, 1, 1)

	lb.Insert(gr, -1)

	return nil
}

func (g *GtkContext) createConfirmPublicIdentity(m *core.UiConfirmPublicIdentity,
	block chan bool) *gtk.Dialog {
	g.DebugUi("createConfirmPublicIdentity")

	d, err := gtk.DialogNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	d.SetTitle("Confirm Public Identity")
	d.SetDefaultSize(640, 480)

	d.AddButton("_Accept", gtk.RESPONSE_ACCEPT)
	d.AddButton("_Reject", gtk.RESPONSE_REJECT)
	d.AddButton("_Cancel", gtk.RESPONSE_CANCEL)

	// add crap
	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	grid.SetColumnHomogeneous(true)

	b, err := d.GetContentArea()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	b.Add(grid)
	b.SetHExpand(true)
	b.SetVExpand(true)

	// listbox
	lb, err := gtk.ListBoxNew()
	if err != nil {
		g.DebugUi("createContacts %v", err)
		return nil
	}
	sw, err := gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		g.DebugUi("createContacts %v", err)
		return nil
	}
	sw.Add(lb)
	lb.SetHExpand(true)
	lb.SetVExpand(true)

	grid.Attach(sw, 0, 0, 2, 4)

	// items
	g.addItem(lb, "Name", m.PublicIdentity.Name)
	g.addItem(lb, "Address", m.PublicIdentity.Address)
	g.addItem(lb, "Fingerprint", m.PublicIdentity.Fingerprint())
	//g.addItem(lb, "Public key", fmt.Sprintf("%0x", m.PublicIdentity.Key))
	//g.addItem(lb, "Signature",
	//	fmt.Sprintf("%0x", m.PublicIdentity.Signature))

	// picture
	pic, err := gtk.ImageNew()
	if err != nil {
		g.DebugUi("addItem %v", err)
		return nil
	}
	pic.SetHExpand(true)
	pic.SetVExpand(true)
	setFromFile(m.PublicIdentity, pic)
	grid.Attach(pic, 0, 2, 2, 2)

	// put on top of main window
	d.SetTransientFor(g.w)
	d.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
	d.ShowAll()

	d.Connect("response", func(_ *gtk.Dialog, rt gtk.ResponseType) {
		msg := &core.UiConfirmPublicIdentityReply{}
		msg.PublicIdentity = m.PublicIdentity
		switch rt {
		case gtk.RESPONSE_ACCEPT:
			msg.State = core.StateAllowed
		case gtk.RESPONSE_REJECT:
			msg.State = core.StateDenied
		default:
			msg.State = core.StateInvalid
		}
		g.SendCore(msg)

		block <- true
	})

	return d
}

func (g *GtkContext) ConfirmPublicIdentity(ci *core.UiConfirmPublicIdentity) {
	g.DebugUi("ConfirmPublicIdentity")
	reply := make(chan bool)
	glib.IdleAdd(func() {
		d := g.createConfirmPublicIdentity(ci, reply)
		if d != nil {
			d.Run()
			d.Destroy()
		} else {
			close(reply)
		}
	})
	<-reply
}
