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
	"github.com/conformal/gotk3/glib"
	"github.com/conformal/gotk3/gtk"
	"github.com/marcopeereboom/mcrypt"
	"github.com/marcopeereboom/scomms/core"
)

// createTrust generates the Message tab.
func (g *GtkContext) createTrust() (widget *gtk.Widget) {
	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("createTrust %v", err)
		return
	}

	grid.SetColumnHomogeneous(true)

	// listbox
	g.trustListbox, err = gtk.ListBoxNew()
	if err != nil {
		g.DebugUi("createTrust %v", err)
		return nil
	}
	sw, err := gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		g.DebugUi("createTrust %v", err)
		return nil
	}
	sw.Add(g.trustListbox)
	g.trustListbox.SetHExpand(true)
	g.trustListbox.SetVExpand(true)

	grid.Attach(sw, 0, 0, 1, 1)

	return &grid.Container.Widget
}

func (g *GtkContext) createIdentifiersDialog(pid *mcrypt.PublicIdentity) *gtk.Dialog {
	g.DebugUi("createIdentifiersDialog")

	d, err := gtk.DialogNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	d.SetTitle("Identifiers")
	d.SetDefaultSize(640, 480)

	d.AddButton("_OK", gtk.RESPONSE_OK)

	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	b, err := d.GetContentArea()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	b.Add(grid)
	b.SetHExpand(true)
	b.SetVExpand(true)

	// picture
	pic, err := gtk.ImageNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	pic.SetHExpand(true)
	pic.SetVExpand(true)
	grid.Attach(pic, 0, 0, 1, 1)
	setFromFile(pid, pic)

	// put on top of main window
	d.SetTransientFor(g.w)
	d.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
	d.ShowAll()

	d.Connect("response", func(_ *gtk.Dialog, rt gtk.ResponseType) {
		switch rt {
		case gtk.RESPONSE_OK:
		}
	})

	return d
}

func (g *GtkContext) createStateDialog(tr *core.TrustRecord) *gtk.Dialog {
	g.DebugUi("createStateDialog")

	d, err := gtk.DialogNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	d.SetTitle("Change State")
	d.SetDefaultSize(640, 480)

	d.AddButton("_OK", gtk.RESPONSE_OK)
	d.AddButton("_Cancel", gtk.RESPONSE_CANCEL)

	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	b, err := d.GetContentArea()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	b.Add(grid)
	b.SetHExpand(true)
	b.SetVExpand(true)

	// radio button
	radio1, err := gtk.RadioButtonNewWithLabel(nil,
		core.State[core.StateAllowed])
	if err != nil {
		return nil
	}
	radioGroup, err := radio1.GetGroup()
	if err != nil {
		return nil
	}
	radio2, err := gtk.RadioButtonNewWithLabel(radioGroup,
		core.State[core.StateDenied])
	if err != nil {
		return nil
	}

	grid.Attach(radio1, 0, 0, 1, 1)
	grid.AttachNextTo(radio2, radio1, gtk.POS_BOTTOM, 2, 1)

	radio1.Show()
	radio2.Show()

	// put on top of main window
	d.SetTransientFor(g.w)
	d.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
	d.ShowAll()

	d.Connect("response", func(_ *gtk.Dialog, rt gtk.ResponseType) {
		switch rt {
		case gtk.RESPONSE_OK:
			newState := core.StateInvalid
			if radio1.GetActive() {
				newState = core.StateAllowed
			} else {
				newState = core.StateDenied
			}
			tr.State = newState

			// tell core to update trust db
			m := &core.UpdateTrustRecord{
				TrustRecord: tr,
			}
			g.SendCore(m)

		case gtk.RESPONSE_CANCEL:
		}
	})

	return d
}

func (g *GtkContext) renderTrustItem(tr *core.TrustRecord) {
	pid := tr.PublicIdentity
	gr, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}

	// state
	// XXX make combo box
	bState, err := gtk.ButtonNew()
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}
	bState.SetLabel(core.State[tr.State])
	bState.SetHExpand(true)
	gr.Attach(bState, 0, 0, 1, 1)
	bState.Connect("clicked", func() {
		glib.IdleAdd(func() {
			d := g.createStateDialog(tr)
			if d != nil {
				d.Run()
				d.Destroy()
			}
		})
	})

	// name
	lblName, err := gtk.LabelNew(pid.Name)
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}
	lblName.SetHExpand(true)
	gr.Attach(lblName, 1, 0, 1, 1)

	// address
	lblAddress, err := gtk.LabelNew(pid.Address)
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}
	lblAddress.SetHExpand(true)
	gr.Attach(lblAddress, 2, 0, 1, 1)

	// fingerprint
	lblFingerprint, err := gtk.LabelNew(pid.Fingerprint())
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}
	lblFingerprint.SetHExpand(true)
	gr.Attach(lblFingerprint, 3, 0, 1, 1)

	// identifiers
	b, err := gtk.ButtonNew()
	if err != nil {
		g.DebugUi("renderTrustItem %v", err)
		return
	}
	b.SetLabel("Identifiers")
	b.SetHExpand(true)
	gr.Attach(b, 4, 0, 1, 1)
	b.Connect("clicked", func() {
		glib.IdleAdd(func() {
			d := g.createIdentifiersDialog(tr.PublicIdentity)
			if d != nil {
				d.Run()
				d.Destroy()
			}
		})
	})

	g.trustListbox.Insert(gr, -1)
}

func (g *GtkContext) RenderTrust(rt *core.UiRenderTrust) {
	g.DebugUi("RenderTrust")

	// we need to recreate the tab here because we can't delete items
	// out of the listbox
	current := g.notebook.GetCurrentPage()
	w := g.createTrust()
	g.notebook.RemovePage(2) // make sure trust stays here!
	g.notebook.AppendPage(w, g.lblTrust)

	for _, v := range rt.TrustRecords {
		if v == nil {
			return
		}
		g.renderTrustItem(v)
	}
	g.trustListbox.ShowAll()

	// this is part of the hack to recreate the tab
	g.notebook.ShowAll()
	g.notebook.SetCurrentPage(current)
}
