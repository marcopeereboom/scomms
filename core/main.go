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
	stdlog "log"
	"os"
	"os/user"
	"runtime"
	"sync"

	"github.com/marcopeereboom/dbglog"
	"github.com/marcopeereboom/mcrypt"
	"github.com/marcopeereboom/queueb"
)

const (
	core = "core"
	ui   = "ui"

	sDbgCore   = 1 << 0
	sDbgUi     = 1 << 1
	sDbgServer = 1 << 2
	sDbgClient = 1 << 3

	scommsDir = "/scomms"
)

type Core struct {
	*queueb.Queueb
	*dbglog.DbgLogger

	// working directory
	scommsDir string

	// identity
	identity *mcrypt.Identity

	// net
	s *Server

	// trust database
	trust           *Trust
	mtxVerifyWaiter sync.Mutex
	verifyWaiters   map[string]func()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func (c *Core) debugCore(format string, args ...interface{}) {
	c.DebugfM(sDbgCore, "[CORE] "+format, args...)
}

func (c *Core) debugClient(format string, args ...interface{}) {
	c.DebugfM(sDbgCore, "[CLNT] "+format, args...)
}

func (c *Core) debugServer(format string, args ...interface{}) {
	c.DebugfM(sDbgCore, "[SRV] "+format, args...)
}

func (c *Core) DebugUi(format string, args ...interface{}) {
	c.DebugfM(sDbgUi, "[UI] "+format, args...)
}

func (c *Core) SendCore(m interface{}) error {
	return c.Send(ui, []string{core}, m)
}

func (c *Core) ReceiveUi() (*queueb.QueuebMessage, error) {
	return c.Receive(ui)
}

func (c *Core) handleUiRenderIdentity(pid *mcrypt.PublicIdentity) {
	// tell UI to render identity
	uir := &UiRenderIdentity{
		PublicIdentity: pid,
	}
	c.Send(core, []string{ui}, uir)

	// start listening
	var err error
	listeners := []string{":12345"}
	c.s, err = NewServer(listeners,
		c.scommsDir+certFilename,
		c.scommsDir+keyFilename,
		c.ServerCallback)
	if err != nil {
		c.debugCore("handleUiRenderIdentity: NewServer %v", err)
		return
	}
}

func (c *Core) renderTrust() (err error) {
	c.debugCore("renderTrust")

	urt := &UiRenderTrust{}
	urt.TrustRecords, err = c.trust.GetAll(c.identity)
	if err != nil {
		return
	}
	c.Send(core, []string{ui}, urt)

	return
}

func (c *Core) handleIdentity() (err error) {
	if c.identityExists() {
		err = c.identityOpen()
		if err != nil {
			c.debugCore("handleIdentity %v", err)
			return
		}

		c.handleUiRenderIdentity(&c.identity.PublicIdentity)
	} else {
		host, err := os.Hostname()
		if err != nil {
			c.debugCore("handleIdentity %v", err)
			return err
		}

		usr, err := user.Current()
		if err != nil {
			c.debugCore("handleIdentity %v", err)
			return err
		}

		m := "Scomms detected that this is the first " +
			"time it is run.\n" +
			"Note that the ID domain *MUST* resolve and be " +
			"reachable on port 12345!\n\n" +
			"ID must be in email address format, e.g. " +
			"jd@mydomain.com\nName is full name, e.g. John Doe\n"

		uci := &UiConfirmIdentity{
			Message: m,
			Name:    usr.Name,
			Address: usr.Username + "@" + host,
		}
		c.Send(core, []string{ui}, uci)
	}

	return
}

func (c *Core) handleUiConfirmIdentityReply(m *UiConfirmIdentityReply) {
	var err error

	// add some sort of dialog for failures
	if m.Error != nil {
		c.debugCore("handleUiConfirmIdentityReply %v", m.Error)
		return
	}

	// setup identity
	c.identity, err = mcrypt.NewIdentity(m.Name, m.Address)
	if err != nil {
		c.debugCore("handleUiConfirmIdentityReply %v", err)
		return
	}
	c.identity.PublicIdentity.Identifiers = m.Identifiers
	err = c.identitySave()
	if err != nil {
		c.debugCore("handleUiConfirmIdentityReply %v", err)
		return
	}

	c.handleUiRenderIdentity(&c.identity.PublicIdentity)
}

func (c *Core) popup(title, format string, args ...interface{}) {
	pu := &UiPopup{
		Title:   title,
		Message: fmt.Sprintf(format, args...),
	}
	c.Send(core, []string{ui}, pu)
}

func (c *Core) handleSendFile(client *Client, sf *SendFile) {
	// go to message phase
	confirmation := Confirmation{
		LookingFor:   sf.To,
		MaxFrameSize: 10 * 1024 * 1024,
	}
	err := client.ConfirmationPhase(&confirmation)
	if err != nil {
		c.popup("Confirmation failed", "%v", err)
		return
	}
	err = client.BecomeReady()
	if err != nil {
		c.popup("Could not enter message phase", "%v", err)
		return
	}

	err = client.Session.SendFile(sf)
	if err != nil {
		c.popup("Send file failed", "%v", err)
		return
	}
}

func (c *Core) p2pConnect(host string) (*Client, error) {
	c.debugCore("p2pConnect")

	client, err := c.NewClientSession(host)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Core) verifyHost(host string, client *Client, callback func()) {
	c.debugCore("verifyHost")

	// this is very tricky code!
	// read at least twice before throwing your hands up in the air!
	finishVerify := func() {
		err := fmt.Errorf("Impossible condition: Error not set " +
			"in verifyHost")
		defer func() {
			if err != nil {
				client.Session.conn.Close()
				c.popup("Public Identity Verification Failed",
					"%v", err)
				return
			}
			callback()
		}()

		if host != client.Session.pid.Address {
			err = fmt.Errorf("Address does not match public "+
				"identity\n\nContacted %v and reply came "+
				"from %v", host, client.Session.pid.Address)
			return
		}

		tr, err := c.trust.Get(c.identity, client.Session.pid)
		if err != nil {
			err = fmt.Errorf("Could not read trust record: %v", err)
			return
		}

		// do more test here
		switch tr.State {
		case StateAllowed:
			err = nil
		case StateDenied:
			err = fmt.Errorf("You previously denied to trust " +
				"this identity")
			return
		case StateQueued:
			err = fmt.Errorf("Remote has queued your " +
				"communication request\n" +
				"Please try again later.")
			return
		default:
			// really can't happen
			err = fmt.Errorf("You canceled trust")
			c.removeVerifyWaiter(client.Session.pid)
			return
		}
	}

	// check if we know this host
	_, err := c.trust.Get(c.identity, client.pid)
	if err != nil {
		cpid := &UiConfirmPublicIdentity{
			PublicIdentity: client.pid,
		}
		c.Send(core, []string{ui}, cpid)

		// wait for something
		c.addVerifyWaiter(client.Session.pid, finishVerify)
	} else {
		finishVerify()
	}
}

func (c *Core) _removeVerifyWaiter(pid *mcrypt.PublicIdentity) {
	c.debugCore("_removeVerifyWaiter %v", pid.Fingerprint())
	delete(c.verifyWaiters, pid.Fingerprint())
}

func (c *Core) removeVerifyWaiter(pid *mcrypt.PublicIdentity) {
	c.mtxVerifyWaiter.Lock()
	defer c.mtxVerifyWaiter.Unlock()

	c._removeVerifyWaiter(pid)
}

func (c *Core) addVerifyWaiter(pid *mcrypt.PublicIdentity, callback func()) {
	c.debugCore("addVerifyWaiter %v", pid.Fingerprint())

	c.mtxVerifyWaiter.Lock()
	defer c.mtxVerifyWaiter.Unlock()

	_, ok := c.verifyWaiters[pid.Fingerprint()]
	if ok {
		c.popup("Public Identity Verification Failed",
			"Impossible condition, check code at %v",
			"addVerifyWaiter")
		return
	}
	c.verifyWaiters[pid.Fingerprint()] = callback
}

func (c *Core) handleVerifyWaiter(pid *mcrypt.PublicIdentity) {
	c.debugCore("handleVerifyWaiter %v", pid.Fingerprint())

	c.mtxVerifyWaiter.Lock()
	defer c.mtxVerifyWaiter.Unlock()

	callback, ok := c.verifyWaiters[pid.Fingerprint()]
	if !ok {
		c.popup("Public Identity Verification Failed",
			"Impossible condition, check code at %v",
			"handleVerifyWaiter")
		return
	}
	callback()
	c._removeVerifyWaiter(pid)
}

// handleIncoming decodes and handles incomming ui messages.
func (c *Core) handleIncoming(msg *queueb.QueuebMessage) {
	switch m := msg.Message.(type) {
	case *UiConfirmIdentityReply:
		c.handleUiConfirmIdentityReply(m)

	case *UiConfirmPublicIdentityReply:
		c.debugCore("%T %v", m, m.State)
		switch m.State {
		case StateAllowed:
		case StateDenied:
		default:
			c.removeVerifyWaiter(m.PublicIdentity)
			return
		}
		err := c.trust.Add(c.identity, m.PublicIdentity, m.State,
			nil, false)
		if err != nil {
			c.popup("Could not add "+m.PublicIdentity.Address+
				"to the trust database", "%v", err)
			return
		}
		c.renderTrust()

		c.handleVerifyWaiter(m.PublicIdentity)

	case *UpdateTrustRecord:
		err := c.trust.Update(c.identity, m.TrustRecord)
		if err != nil {
			c.popup("Could not update  "+m.TrustRecord.PublicIdentity.Address+
				"in the trust database", "%v", err)
			return
		}
		c.renderTrust()

	case *UiReady:
		c.handleIdentity()
		c.renderTrust()

	case *Shutdown:
		// tell UI to shut down
		c.Send(core, []string{ui}, &Exit{})

	case *SendFile:
		// get connected
		client, err := c.p2pConnect(m.To)
		if err != nil {
			c.popup("Connection Failed", "%v", err)
			return
		}
		c.verifyHost(m.To, client,
			func() { c.handleSendFile(client, m) })

	default:
		c.debugCore("unhandled message %T", msg.Message)
	}
}

func (c *Core) Start() {
	c.debugCore("started")
	go func() {
		for {
			msg, err := c.Receive(core)
			if err != nil {
				c.debugCore("receive error %v", err)
				return
			}
			if msg.Error() != nil {
				// this should potentially be displayed to user
				c.debugCore("message error %v", msg.Error())
				continue
			}
			c.debugCore("received %T", msg.Message)
			switch msg.Message.(type) {
			case *Exit:
				return
			default:
				c.handleIncoming(msg)
			}
		}
	}()
}

func New() (*Core, error) {
	var err error

	// setup logging
	c := Core{
		DbgLogger:     dbglog.New(os.Stderr, "", stdlog.LstdFlags),
		verifyWaiters: make(map[string]func()),
	}
	var mask uint64
	mask |= sDbgUi
	mask |= sDbgCore
	mask |= sDbgClient
	mask |= sDbgServer
	c.DbgLogger.SetMask(mask)
	c.DbgLogger.Enable()

	// setup messaging
	c.Queueb, err = queueb.New("queuebs", 50)
	if err != nil {
		return nil, err
	}
	err = c.Queueb.Register(ui, 10)
	if err != nil {
		return nil, err
	}
	err = c.Queueb.Register(core, 50)
	if err != nil {
		return nil, err
	}

	// setup paths
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	c.scommsDir = usr.HomeDir + scommsDir
	err = os.MkdirAll(c.scommsDir, 0700)
	if err != nil {
		return nil, err
	}

	c.trust, err = NewTrust(c.scommsDir)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
