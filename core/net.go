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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/marcopeereboom/mcrypt"
)

// session progression
//
// session phase
//	1. Client contacts server over a websocket
//	2. Client sends session identity
//	3. Server sends session identity
//
//	all messages are encrypted using session identity going forward
//
// identity phase
//	4. Client sends actual identity
//	5. Server sends actual identity
//
// confirmation phase
//	6. Client & Server determine if they like each other
//		Client prompts user for fingerprint acceptance
//		Server queues fingerprint acceptance
//
// message phase
//	7. Client & Server can exchange	RPC messages

const (
	phaseStartOfDay   = 0
	phaseSession      = 10
	phaseIdentity     = 20
	phaseConfirmation = 30
	phaseMessage      = 40

	rpcTimeoutSeconds = 10

	RpcIdentity        = "identity"
	RpcConfirmation    = "confirmation"
	RpcSendFileCommand = "sendfile"
)

type Rpc struct {
	Command string      `json:"command"`
	Payload interface{} `json:"payload"`
}

type Confirmation struct {
	LookingFor   string `json:"lookingfor"`
	MaxFrameSize int    `json:"marxframesize"`
	Error        string `json:"error"`
	State        int    `json:"state"`
}

type RpcSendFile struct {
	Filename string `json:"filename"`
	Mime     string `json:"mime"`
	Content  []byte `json:"content"`
}

type Session struct {
	pid          *mcrypt.PublicIdentity // actual identity
	peer         *mcrypt.PublicIdentity // actual peer identity
	sid          *mcrypt.Identity       // session identity
	speer        *mcrypt.PublicIdentity // session peer identity
	conn         *websocket.Conn        // websocket
	confirmation *Confirmation          // session parameters
	server       bool                   // server or client
	phase        int                    // session progression
}

func (s *Session) BecomeReady() (err error) {
	if s.phase != phaseConfirmation {
		return fmt.Errorf("invalid phase")
	}
	if s.peer == nil {
		return fmt.Errorf("no remote public identity")
	}
	if s.sid == nil {
		return fmt.Errorf("no session identity")
	}
	if s.speer == nil {
		return fmt.Errorf("no peer session identity")
	}
	if s.conn == nil {
		return fmt.Errorf("no websocket")
	}
	if s.confirmation == nil {
		return fmt.Errorf("no confirmation")
	}

	// move phase forward
	s.phase = phaseMessage

	return nil
}

type Client struct {
	Session
}

type Server struct {
	listeners []net.Listener
}

func NewServer(listenAddrs []string, cert, key string,
	callback func(*Session)) (*Server, error) {
	keypair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	ipv4ListenAddrs, ipv6ListenAddrs, err := parseListeners(listenAddrs)
	listeners := make([]net.Listener, 0,
		len(ipv6ListenAddrs)+len(ipv4ListenAddrs))
	for _, addr := range ipv4ListenAddrs {
		listener, err := tls.Listen("tcp4", addr, &tlsConfig)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
	}

	for _, addr := range ipv6ListenAddrs {
		listener, err := tls.Listen("tcp6", addr, &tlsConfig)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no valid listen address")
	}
	s := Server{
		listeners: listeners,
	}

	serveMux := http.NewServeMux()
	httpServer := &http.Server{
		Handler:     serveMux,
		ReadTimeout: time.Second * rpcTimeoutSeconds,
	}
	serveMux.HandleFunc("/tubes", func(w http.ResponseWriter, r *http.Request) {
		var (
			err     error
			session *Session = &Session{server: true}
		)
		session.conn, err = websocket.Upgrade(w, r, w.Header(), 4096, 4096)
		if err != nil {
			// XXX
			fmt.Printf("Cannot websocket upgrade client %s: %v",
				r.RemoteAddr, err)
			return
		}
		go callback(session)
	})

	for _, listener := range s.listeners {
		go func(listener net.Listener) {
			err = httpServer.Serve(listener)
		}(listener)
	}

	return &s, nil
}

func NewClient(address, port string) (*Client, error) {
	var err error
	addr := net.JoinHostPort(address, port)
	url := "wss://" + addr + "/tubes"
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: rpcTimeoutSeconds * time.Second,
		TLSClientConfig:  tlsConfig,
	}

	c := Client{}
	c.conn, _, err = dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (s *Session) sessionPhaseSend() (err error) {
	// send session identity
	s.sid, err = mcrypt.NewIdentity("", "")
	if err != nil {
		return
	}
	err = s.conn.WriteJSON(s.sid.PublicIdentity)
	return
}

func (s *Session) sessionPhaseRecv() (err error) {
	// receive peer session identity
	err = s.conn.ReadJSON(&s.speer)
	return
}

func (s *Session) SessionPhase() (err error) {
	if s.phase != phaseStartOfDay {
		return fmt.Errorf("invalid phase")
	}

	if s.server == true {
		err = s.sessionPhaseRecv()
		if err != nil {
			return
		}
		err = s.sessionPhaseSend()
	} else {
		err = s.sessionPhaseSend()
		if err != nil {
			return
		}
		err = s.sessionPhaseRecv()
	}

	if err == nil {
		// move phase forward
		s.phase = phaseSession
	}

	return
}

func (s *Session) identityPhaseSend(pid *mcrypt.PublicIdentity) (err error) {
	err = s.RpcSend(pid)
	return
}

func (s *Session) identityPhaseRecv() (err error) {
	var (
		c  interface{}
		ok bool
	)
	c, err = s.RpcReceive()
	s.peer, ok = c.(*mcrypt.PublicIdentity)
	if !ok {
		err = fmt.Errorf("expected public identity")
	}

	return
}

func (s *Session) IdentityPhase(pid *mcrypt.PublicIdentity) (err error) {
	if s.phase != phaseSession {
		return fmt.Errorf("invalid phase")
	}

	if s.server == true {
		err = s.identityPhaseRecv()
		if err != nil {
			return
		}
		err = s.identityPhaseSend(pid)
	} else {
		err = s.identityPhaseSend(pid)
		if err != nil {
			return
		}
		err = s.identityPhaseRecv()
	}

	if err == nil {
		// move phase forward
		s.phase = phaseIdentity
		s.pid = pid
	}

	return
}

func (s *Session) confirmationPhaseSend(c *Confirmation) (err error) {
	err = s.RpcSend(c)
	return
}

func (s *Session) confirmationPhaseRecv() (err error) {
	var (
		c  interface{}
		ok bool
	)
	c, err = s.RpcReceive()
	if err != nil {
		return
	}
	s.confirmation, ok = c.(*Confirmation)
	if !ok {
		err = fmt.Errorf("expected confirmation")
	}

	return
}

func (s *Session) ConfirmationPhase(c *Confirmation) (err error) {
	if s.phase != phaseIdentity {
		return fmt.Errorf("invalid phase")
	}

	if s.server == true {
		err = s.confirmationPhaseRecv()
		if err != nil {
			return
		}
		if s.pid.Address != s.confirmation.LookingFor {
			// return error and send it to client as well
			err = fmt.Errorf("unknown user %v",
				s.confirmation.LookingFor)
			c.Error = err.Error()
			err = s.confirmationPhaseSend(c)
			return
		}
		err = s.confirmationPhaseSend(c)
	} else {
		err = s.confirmationPhaseSend(c)
		if err != nil {
			return
		}
		err = s.confirmationPhaseRecv()
		if err != nil {
			return
		}
		// see if an error came back
		if s.confirmation.Error != "" {
			err = fmt.Errorf("Remote error: %v",
				s.confirmation.Error)
		}
	}

	if err == nil {
		// move phase forward
		s.phase = phaseConfirmation
	}

	return
}

func (s *Session) DefaultSession(pid *mcrypt.PublicIdentity) (err error) {
	defer func() {
		if err != nil {
			s.conn.Close()
		}
	}()

	err = s.SessionPhase()
	if err != nil {
		return
	}
	err = s.IdentityPhase(pid)
	if err != nil {
		return
	}

	return
}

func (s *Session) RpcReceive() (interface{}, error) {
	// read mcrypt message
	msg := &mcrypt.Message{}
	err := s.conn.ReadJSON(msg)
	if err != nil {
		return nil, err
	}

	// decrypt
	j, err := s.sid.Decrypt(s.speer.Key, msg)
	if err != nil {
		return nil, err
	}

	// generate an objmap so we dont unmarshal it 3 times
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(j, &objmap)
	if err != nil {
		return nil, err
	}

	// fish command out
	var command string
	err = json.Unmarshal(objmap["command"], &command)
	if err != nil {
		return nil, err
	}

	// handle command
	switch command {
	case RpcIdentity:
		if s.phase != phaseSession {
			return nil, fmt.Errorf("can't receive identity; " +
				"wrong phase")
		}
		ri := mcrypt.PublicIdentity{}
		err = json.Unmarshal(objmap["payload"], &ri)
		if err != nil {
			return nil, err
		}
		return &ri, nil
	case RpcConfirmation:
		if s.phase != phaseIdentity {
			return nil, fmt.Errorf("can't receive confirmation; " +
				"wrong phase")
		}
		c := Confirmation{}
		err = json.Unmarshal(objmap["payload"], &c)
		if err != nil {
			return nil, err
		}
		return &c, nil
	case RpcSendFileCommand:
		if s.phase != phaseMessage {
			return nil, fmt.Errorf("not in message phase")
		}
		rsf := RpcSendFile{}
		err = json.Unmarshal(objmap["payload"], &rsf)
		if err != nil {
			return nil, err
		}
		return &rsf, nil
	default:
		return nil, fmt.Errorf("invalid RPC command %v", command)
	}

	return nil, fmt.Errorf("NOT REACHED")
}

func (s *Session) RpcSend(command interface{}) error {
	rpc := &Rpc{}
	switch command.(type) {
	case *mcrypt.PublicIdentity:
		if s.phase != phaseSession {
			return fmt.Errorf("can't send identity; " +
				"wrong phase")
		}
		rpc.Command = RpcIdentity
	case *Confirmation:
		if s.phase != phaseIdentity {
			return fmt.Errorf("can't send confirmation; " +
				"wrong phase")
		}
		rpc.Command = RpcConfirmation
	case *RpcSendFile:
		if s.phase != phaseMessage {
			return fmt.Errorf("not in message phase")
		}
		rpc.Command = RpcSendFileCommand
	default:
		return fmt.Errorf("invalid command type %T", command)
	}
	rpc.Payload = command

	// json
	j, err := json.Marshal(rpc)
	if err != nil {
		return err
	}

	// encrypt
	ej, err := s.sid.Encrypt(s.speer.Key, j)
	if err != nil {
		return err
	}

	// send
	err = s.conn.WriteJSON(ej)
	if err != nil {
		return err
	}

	return nil
}

// establish a new session and return the session
func (c *Core) NewClientSession(to string) (*Client, error) {
	var (
		a   []string
		err error
	)

	a = strings.Split(to, "@")
	if len(a) != 2 {
		return nil, fmt.Errorf("invalid destination %v", to)
	}

	client, err := NewClient(a[1], "12345")
	if err != nil {
		return nil, err
	}

	err = client.DefaultSession(&c.identity.PublicIdentity)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Core) ServerCallback(s *Session) {
	c.debugServer("ServerCallback")
	defer func() {
		//s.conn.Close()
		c.debugServer("ServerCallback done")
	}()

	err := s.DefaultSession(&c.identity.PublicIdentity)
	if err != nil {
		c.debugServer("ServerCallback DefaultSession %v", err)
		return
	}

	// go to message phase
	confirmation := Confirmation{
		MaxFrameSize: 10 * 1024 * 1024,
	}

	// see if we trust this identity
	tr, err := c.trust.Get(c.identity, s.pid)
	if err != nil {
		// not seen before, queue trust
		err = c.trust.Add(c.identity, s.pid, StateQueued, nil, false)
		if err != nil {
			c.debugServer("ServerCallback failed to add trust %v",
				err)
			return
		}
		confirmation.State = StateQueued
		c.renderTrust()
	} else {
		// verify trust
		if tr.State != StateAllowed {
			c.debugServer("ServerCallback denied access")
			return
		}
	}

	err = s.ConfirmationPhase(&confirmation)
	if err != nil {
		c.debugServer("ServerCallback ConfirmationPhase %v", err)
		return
	}

	// if we were queued abort Confirmation sequence
	if confirmation.State == StateQueued {
		c.debugServer("ServerCallback ConfirmationPhase went queued")
		return
	}

	err = s.BecomeReady()
	if err != nil {
		c.debugServer("ServerCallback BecomeReady %v", err)
		return
	}

	for {
		cmd, err := s.RpcReceive()
		if err != nil {
			c.debugServer("ServerCallback RpcReceive %v", err)
			return
		}
		switch command := cmd.(type) {
		case *RpcSendFile:
			err := c.serverSendFile(command, s.peer)
			if err != nil {
				c.debugServer("ServerCallback "+
					"serverSendFile %v", err)
			}
		default:
			c.debugServer("ServerCallback invalid type %T", cmd)
		}
	}
}

func (s *Session) SendFile(sf *SendFile) error {
	var err error

	// construct command
	rsf := RpcSendFile{
		Filename: path.Base(sf.Filename),
		Mime:     sf.Mime,
	}
	rsf.Content, err = ioutil.ReadFile(sf.Filename)
	if err != nil {
		return err
	}

	return s.RpcSend(&rsf)
}

// This structure is saved alongside content with some interesting information.
// this needs lots more stuff, like encrypt at rest, keys it was sent with etc
// TODO this probably deserves it's own package
type MetaRecord struct {
	Version uint32    `json:"version"`
	Mime    string    `json:"mime"`
	Created time.Time `json:"created"`
}

func (c *Core) serverSendFile(rsf *RpcSendFile,
	peer *mcrypt.PublicIdentity) error {
	// create holding area
	targetDir := c.scommsDir + "/spool/" + peer.Address + "/"
	err := os.MkdirAll(targetDir, 0700)
	if err != nil {
		return err
	}

	// see if we were sent a filename hint
	filename := ""
	if rsf.Filename == "" {
		filename, err = newRandomFileName(targetDir, "unknown")
		if err != nil {
			return err
		}
	} else {
		// sanitize filename
		filename = rsf.Filename
	}

	// look for dups
	_, err = os.Stat(filename)
	if err == nil {
		// exists, create temp file instead
		filename, err = newRandomFileName(targetDir, filename)
		if err != nil {
			return err
		}
	}

	// write meta
	meta := MetaRecord{
		Version: 1,
		Mime:    rsf.Mime,
		Created: time.Now(),
	}
	metaJson, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(targetDir+filename+".meta", metaJson, 0600)
	if err != nil {
		return err
	}

	// write content
	err = ioutil.WriteFile(targetDir+filename, rsf.Content, 0600)
	if err != nil {
		return err
	}

	// TODO move this notification to Gui
	c.popup("New message",
		"You have received a message and it was saved in: %v\n",
		targetDir+filename)

	return nil
}

// Generate a random filename.
func newRandomFileName(tmpDir, prefix string) (string, error) {
	tmpFd, err := ioutil.TempFile(tmpDir, prefix)
	if err != nil {
		return "", err
	}
	filename := path.Base(tmpFd.Name())
	tmpFd.Close()
	return filename, nil

}

// parseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them.  This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6".  It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func parseListeners(addrs []string) ([]string, []string, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is not a valid IP "+
				"address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, nil
}
