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
	"io/ioutil"
	"os"

	"github.com/conformal/gotk3/gdk"
	"github.com/conformal/gotk3/glib"
	"github.com/conformal/gotk3/gtk"
	"github.com/marcopeereboom/mcrypt"
	"github.com/marcopeereboom/scomms/core"
)

// XXX temp file stuff must be rewritten to not go in /tmp

type GtkContext struct {
	*core.Core

	// gtk stuff
	w        *gtk.Window
	notebook *gtk.Notebook

	// overview tab
	nameEntry        *gtk.Entry
	addressEntry     *gtk.Entry
	fingerprintEntry *gtk.Entry
	picture          *gtk.Image

	// trust tab
	trustListbox *gtk.ListBox
	lblTrust     *gtk.Label
}

func (g *GtkContext) Exit() {
	// shut...down...EVERYTHING
	gtk.MainQuit()
}

func resizePic(pic *gtk.Image) {
	pb := pic.GetPixbuf()

	var w, h, margin float32
	margin = 0.9 // 90% of image size
	if pb.GetWidth() < pb.GetHeight() {
		// scale by width
		w = float32(pic.GetAllocatedWidth()) * margin
		h = float32(pb.GetHeight()) / float32(pb.GetWidth()) *
			(float32(pic.GetAllocatedWidth()) * margin)
	} else {
		// scale by height
		h = float32(pic.GetAllocatedHeight()) * margin
		w = float32(pb.GetWidth()) / float32(pb.GetHeight()) *
			(float32(pic.GetAllocatedHeight()) * margin)
	}
	pbScale, err := pb.ScaleSimple(int(w), int(h), gdk.INTERP_BILINEAR)
	if err != nil {
		return
	}
	pic.SetFromPixbuf(pbScale)
	return
}

func findIdentifier(pid *mcrypt.PublicIdentity, id string) (*mcrypt.Identifier, error) {
	for _, v := range pid.Identifiers {
		if v.Description == core.ProfilePicture {
			return v, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func setFromFile(pid *mcrypt.PublicIdentity, img *gtk.Image) {
	id, err := findIdentifier(pid, core.ProfilePicture)
	if err != nil {
		return
	}
	tmpDir, err := ioutil.TempDir(os.TempDir(), "scomms")
	if err != nil {
		return
	}
	tmpFd, err := ioutil.TempFile(tmpDir, "pic")
	if err != nil {
		return
	}
	tmpFile := tmpFd.Name()
	tmpFd.Close() // we no longer need the fd
	defer os.Remove(tmpFile)

	ioutil.WriteFile(tmpFile, id.Content, 0600)
	img.SetFromFile(tmpFile)

	// this works most of the time; just not on first exposure of notebook
	img.Connect("map", resizePic)
}

func (g *GtkContext) RenderIdentity(uri *core.UiRenderIdentity) {
	glib.IdleAdd(func() {
		g.nameEntry.SetText(uri.PublicIdentity.Name)
		g.addressEntry.SetText(uri.PublicIdentity.Address)
		g.fingerprintEntry.SetText(uri.PublicIdentity.Fingerprint())
		setFromFile(uri.PublicIdentity, g.picture)
	})
}

func GtkInit(c *core.Core) (*GtkContext, error) {
	var err error

	gtk.Init(nil)

	g := GtkContext{Core: c}

	// create window
	g.w, err = gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return nil, err
	}
	g.w.SetTitle("Secure Communications")
	g.w.Connect("destroy", func() {
		g.SendCore(&core.Shutdown{})
	})

	// create grid
	grid, err := gtk.GridNew()
	if err != nil {
		return nil, err
	}
	grid.SetOrientation(gtk.ORIENTATION_VERTICAL)

	// create notebook
	g.notebook, err = gtk.NotebookNew()
	if err != nil {
		return nil, err
	}
	g.notebook.SetHExpand(true)
	g.notebook.SetVExpand(true)
	grid.Add(g.notebook)

	// create overview tab
	l, err := gtk.LabelNew("Overview")
	if err != nil {
		return nil, err
	}
	g.notebook.AppendPage(g.createOverview(), l)

	// create message tab
	l, err = gtk.LabelNew("Message")
	if err != nil {
		return nil, err
	}
	g.notebook.AppendPage(g.createMessage(), l)

	// create trust tab
	g.lblTrust, err = gtk.LabelNew("Trust")
	if err != nil {
		return nil, err
	}
	g.notebook.AppendPage(g.createTrust(), g.lblTrust)

	// add _o/ to window and show it
	g.w.Add(grid)
	g.w.SetDefaultSize(800, 600)
	g.w.ShowAll()

	// run gtk
	go gtk.Main()

	return &g, err
}

// createMessage generates the Message tab.
func (g *GtkContext) createMessage() (widget *gtk.Widget) {
	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("createMessage %v", err)
		return
	}

	grid.SetColumnHomogeneous(true)

	// recipient
	lbl, err := gtk.LabelNew("To identity")
	if err != nil {
		g.DebugUi("createMessage %v", err)
		return
	}
	grid.Attach(lbl, 0, 0, 1, 1)

	sendEntry, err := gtk.EntryNew()
	if err != nil {
		g.DebugUi("createMessage %v", err)
		return
	}
	sendEntry.SetHExpand(true)
	//sendEntry.SetText(g.Id)
	grid.Attach(sendEntry, 1, 0, 1, 1)

	b, err := gtk.ButtonNew()
	if err != nil {
		g.DebugUi("createMessage %v", err)
		return
	}
	b.SetLabel("Send")
	b.SetHExpand(true)
	grid.Attach(b, 2, 0, 1, 1)

	tv, err := gtk.TextViewNew()
	if err != nil {
		g.DebugUi("createMessage %v", err)
		return
	}
	tv.SetHExpand(true)
	tv.SetVExpand(true)
	grid.Attach(tv, 0, 1, 3, 1)

	b.Connect("clicked", func() {
		g.DebugUi("createMessage clicked")

		tmpDir, err := ioutil.TempDir(os.TempDir(), "scomms")
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}
		tmpFd, err := ioutil.TempFile(tmpDir, "scmsg")
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}
		tmpFile := tmpFd.Name()
		tmpFd.Close() // we no longer need the fd
		bf, err := tv.GetBuffer()
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}
		start, end := bf.GetBounds()
		text, err := bf.GetText(start, end, true)
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}
		err = ioutil.WriteFile(tmpFile, []byte(text), 0600)
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}

		to, err := sendEntry.GetText()
		if err != nil {
			g.DebugUi("createMessage %v", err)
			return
		}
		m := &core.SendFile{
			To:       to,
			Filename: tmpFile,
			Mime:     "message/rfc822", // TODO lies for now
		}
		g.SendCore(m)
	})

	return &grid.Container.Widget
}

// Generate overview tab.
func (g *GtkContext) createOverview() (widget *gtk.Widget) {
	grid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}

	// name
	lbl, err := gtk.LabelNew("Name")
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}
	lbl.SetHAlign(gtk.ALIGN_START)
	grid.Attach(lbl, 0, 1, 1, 1)

	g.nameEntry, err = gtk.EntryNew()
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}
	g.nameEntry.Set("editable", false)
	g.nameEntry.SetHExpand(true)
	grid.Attach(g.nameEntry, 1, 1, 1, 1)

	// address
	lbl, err = gtk.LabelNew("Address")
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}
	lbl.SetHAlign(gtk.ALIGN_START)
	grid.Attach(lbl, 0, 2, 1, 1)

	g.addressEntry, err = gtk.EntryNew()
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}
	g.addressEntry.Set("editable", false)
	g.addressEntry.SetHExpand(true)
	grid.Attach(g.addressEntry, 1, 2, 1, 1)

	// fingerprint
	lbl, err = gtk.LabelNew("Fingerprint")
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
	}
	lbl.SetHAlign(gtk.ALIGN_START)
	grid.Attach(lbl, 0, 3, 1, 1)

	g.fingerprintEntry, err = gtk.EntryNew()
	if err != nil {
		g.DebugUi("createOverview %v", err)
		return
		return
	}
	g.fingerprintEntry.Set("editable", false)
	g.fingerprintEntry.SetHExpand(true)
	grid.Attach(g.fingerprintEntry, 1, 3, 1, 1)

	// picture
	g.picture, err = gtk.ImageNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	g.picture.SetHExpand(true)
	g.picture.SetVExpand(true)
	grid.Attach(g.picture, 0, 4, 2, 1)

	return &grid.Container.Widget
}

// Create a dialog to allow user to change id and name.
// This is a blocking call.
func (g *GtkContext) createChangeDefaultsDialog(m *core.UiConfirmIdentity,
	block chan bool) *gtk.Dialog {
	g.DebugUi("createChangeDefaultsDialog")

	d, err := gtk.DialogNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	d.SetTitle("Change identity defaults")
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

	lbl, err := gtk.LabelNew(m.Message)
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.Attach(lbl, 0, 0, 2, 1)

	// address
	lbl, err = gtk.LabelNew("Address")
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.Attach(lbl, 0, 1, 1, 1)

	addressEntry, err := gtk.EntryNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	addressEntry.SetHExpand(true)
	addressEntry.SetVExpand(true)
	addressEntry.Connect("activate", func() {
		d.Emit("response", gtk.RESPONSE_OK, nil)
	})
	addressEntry.SetText(m.Address)
	grid.Attach(addressEntry, 1, 1, 1, 1)

	// name
	lbl, err = gtk.LabelNew("Name")
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	grid.Attach(lbl, 0, 2, 1, 1)

	nameEntry, err := gtk.EntryNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	nameEntry.SetHExpand(true)
	nameEntry.SetVExpand(true)
	nameEntry.Connect("activate", func() {
		d.Emit("response", gtk.RESPONSE_OK, nil)
	})
	nameEntry.SetText(m.Name)
	grid.Attach(nameEntry, 1, 2, 1, 1)

	// picture
	pic, err := gtk.ImageNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	pic.SetHExpand(true)
	pic.SetVExpand(true)

	// event for pic
	event, err := gtk.EventBoxNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	event.Add(pic)

	notebook, err := gtk.NotebookNew()
	if err != nil {
		g.DebugUi("%v", err)
	}
	notebook.SetHExpand(true)
	notebook.SetVExpand(true)
	notebook.SetShowTabs(false)
	notebook.AppendPage(event, nil)

	// picture file chooser
	fcGrid, err := gtk.GridNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	fc, err := gtk.FileChooserWidgetNew(gtk.FILE_CHOOSER_ACTION_OPEN)
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	fc.SetHExpand(true)
	fc.SetVExpand(true)
	fcGrid.Attach(fc, 0, 0, 3, 3)
	//button
	fcButton, err := gtk.ButtonNew()
	if err != nil {
		g.DebugUi("%v", err)
		return nil
	}
	fcButton.SetLabel("Select")
	fcButton.SetHExpand(true)
	fcGrid.Attach(fcButton, 1, 3, 1, 1)
	fcButton.Connect("clicked", func() {
		notebook.SetCurrentPage(0)
		pic.SetFromFile(fc.GetFilename())
	})

	notebook.AppendPage(fcGrid, nil)

	event.Connect("button_press_event", func() {
		notebook.SetCurrentPage(1)
	})

	grid.Attach(notebook, 0, 3, 2, 2)

	// put on top of main window
	d.SetTransientFor(g.w)
	d.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
	d.ShowAll()

	notebook.SetCurrentPage(1)

	d.Connect("response", func(_ *gtk.Dialog, rt gtk.ResponseType) {
		switch rt {
		case gtk.RESPONSE_OK:
			ucir := &core.UiConfirmIdentityReply{}

			idf, err := mcrypt.NewIdentifier(core.ProfilePicture,
				fc.GetFilename())
			if err == nil {
				ucir.Identifiers = []*mcrypt.Identifier{idf}
			}

			ucir.Address, err = addressEntry.GetText()
			if err != nil {
				g.DebugUi("%v", err)
				ucir.Error = err
			}
			ucir.Name, err = nameEntry.GetText()
			if err != nil {
				g.DebugUi("%v", err)
				ucir.Error = err
			}
			g.SendCore(ucir)
		}
		block <- true
	})

	return d
}

// ChangeDefaults prompts the user to confirm ID and name.
// Won't return until dialog completes.
func (g *GtkContext) ConfirmIdentity(ci *core.UiConfirmIdentity) {
	g.DebugUi("ConfirmIdentity")
	reply := make(chan bool)
	glib.IdleAdd(func() {
		d := g.createChangeDefaultsDialog(ci, reply)
		if d != nil {
			d.Run()
			d.Destroy()
		} else {
			close(reply)
		}
	})
	_ = <-reply
}

// Display annoying message.
func (g *GtkContext) Popup(p *core.UiPopup) {
	g.DebugUi("PopUp")
	b := make(chan bool)
	glib.IdleAdd(func() {
		message := p.Message
		mDialog := gtk.MessageDialogNew(g.w, 0,
			gtk.MESSAGE_ERROR, gtk.BUTTONS_OK,
			message)
		mDialog.SetTitle(p.Title)
		mDialog.Show()
		mDialog.Run()
		mDialog.Destroy()
		b <- true
	})
	_ = <-b
}
