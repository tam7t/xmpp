// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// Conn represents a connection to an XMPP server.
type Conn struct {
	out          io.Writer
	in           *xml.Decoder
	jid          string
	localpart    string
	domainpart   string
	resourcepart string
	state        int
}

func (c *Conn) SendStanza(s interface{}) error {
	return xml.NewEncoder(c.out).Encode(s)
}

type AccountManager interface {
	Authenticate(username, password string) (success bool, err error)
	CreateAccount(username, password string) (success bool, err error)
	OnlineRoster(jid string) (online []string, err error)
}

type Logging interface {
	Debug(string) error
	Info(string) error
	Error(string) error
}

// Config contains options for an XMPP connection.
type Server struct {
	// what domain to use?
	Domain string

	// SkipTLS, if true, causes the TLS handshake to be skipped.
	// WARNING: this should only be used if Conn is already secure.
	SkipTLS bool
	// TLSConfig contains the configuration to be used by the TLS
	// handshake. If nil, sensible defaults will be used.
	TLSConfig *tls.Config

	// AccountManager handles messages that the server must respond to
	// such as authentication and roster management
	Accounts AccountManager

	// How the client notifies the server who the connection is
	// and how to send messages to the connection JID
	ConnectBus chan<- Connect

	// notify server that the client has disconnected
	DisconnectBus chan<- Disconnect

	// How the client sends messages to other clients
	MessageBus chan<- Message

	// Injectable logging interface
	Log Logging
}

func makeInOut(conn io.ReadWriter) (in *xml.Decoder, out io.Writer) {
	in = xml.NewDecoder(conn)
	out = conn
	return
}

// Represents a generic XMPP message to send to the To Jid
type Message struct {
	To   string
	Data interface{}
}

// Register a channel where the server can send messages to the specific Jid
type Connect struct {
	Jid      string
	Receiver chan<- interface{}
}

type Disconnect struct {
	Jid string
}

func (s *Server) TcpAnswer(conn net.Conn) (err error) {
	var c = new(Conn)
	var se xml.StartElement
	var val interface{}
	var messagesToSendClient chan interface{}

	c.state = STATE_INIT

	s.Log.Info("Accepting TCP connection")

	c.in, c.out = makeInOut(conn)
	c.domainpart = s.Domain

	for {
		switch c.state {
		case STATE_INIT:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			// TODO: check that se is a stream
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")
			c.state = STATE_FIRST_STREAM
		case STATE_FIRST_STREAM:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			// TODO: ensure urn:ietf:params:xml:ns:xmpp-tls
			c.state = STATE_TLS_UPGRADE_REQUESTED
		case STATE_TLS_UPGRADE_REQUESTED:
			fmt.Fprintf(c.out, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
			tlsConn := tls.Server(conn, s.TLSConfig)
			tlsConn.Handshake()
			c.in, c.out = makeInOut(tlsConn)
			c.state = STATE_TLS_UPGRADED
		case STATE_TLS_UPGRADED:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			// TODO: ensure check that se is a stream
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>")
			c.state = STATE_TLS_START_STREAM
		case STATE_TLS_START_STREAM:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			// TODO: check what client sends, auth or register
			c.state = STATE_TLS_AUTH
		case STATE_TLS_AUTH:
			// read the full auth stanza
			_, val, err = read(c.in, se)
			if err != nil {
				s.errorOut(c, errors.New("Unable to read auth stanza"))
			}
			switch v := val.(type) {
			case *saslAuth:
				data, err := base64.StdEncoding.DecodeString(v.Body)
				if err != nil {
					s.errorOut(c, err)
				}
				info := strings.Split(string(data), "\x00")
				// should check that info[1] starts with client.jid
				success, err := s.Accounts.Authenticate(info[1], info[2])
				if err != nil {
					s.errorOut(c, err)
				}
				if success {
					c.localpart = info[1]
					fmt.Fprintf(c.out, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
					c.state = STATE_AUTHED_START
				} else {
					fmt.Fprintf(c.out, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")
				}
			default:
				// expected authentication
				s.errorOut(c, errors.New("Expected authentication"))
			}
		case STATE_AUTHED_START:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>")
			c.state = STATE_AUTHED_STREAM
		case STATE_AUTHED_STREAM:
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			// check that it's a bind request
			// read bind request
			_, val, err := read(c.in, se)
			if err != nil {
				s.errorOut(c, err)
			}
			switch v := val.(type) {
			case *ClientIQ:
				// TODO: actually validate that it's a bind request
				if v.Bind.Resource == "" {
					c.resourcepart = makeResource()
				} else {
					s.errorOut(c, errors.New("Invalid bind request"))
				}
				c.jid = c.localpart + "@" + c.domainpart + "/" + c.resourcepart
				fmt.Fprintf(c.out, "<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", v.Id, c.jid)

				// fire off go routine to handle messages
				messagesToSendClient = make(chan interface{})
				go s.handle(c, messagesToSendClient)
				s.ConnectBus <- Connect{Jid: c.jid, Receiver: messagesToSendClient}

				c.state = STATE_NORMAL
			default:
				s.errorOut(c, errors.New("Expected ClientIQ message"))
			}
		case STATE_NORMAL:
			/* read from socket */
			se, err = scan(c.in)
			if err != nil {
				s.errorOut(c, err)
			}
			_, val, _ = read(c.in, se)
			switch v := val.(type) {
			case *ClientMessage:
				s.MessageBus <- Message{To: v.To, Data: val}
			case *ClientIQ:
				// handle things we need to handle
				if string(v.Query) == "<query xmlns='jabber:iq:roster'/>" {
					// respond with roster
					roster, _ := s.Accounts.OnlineRoster(c.jid)
					msg := "<iq id='" + v.Id + "' to='" + v.From + "' type='result'><query xmlns='jabber:iq:roster' ver='ver7'>"
					for _, v := range roster {
						msg = msg + "<item jid='" + v + "'/>"
					}
					msg = msg + "</query></iq>"

					messagesToSendClient <- msg
				} else {
					s.MessageBus <- Message{To: v.To, Data: val}
				}
			default:
				s.Log.Error(fmt.Sprintf("Ignoring unknown stanza: %s", val))
			}
		case STATE_CLOSED:
			s.Log.Debug("Done state")
			close(messagesToSendClient)
			s.DisconnectBus <- Disconnect{Jid: c.jid}
			conn.Close()
			break
		}
	}
}

func (s *Server) errorOut(conn *Conn, err error) {
	s.Log.Error(err.Error())
	conn.state = STATE_CLOSED
}

func (s *Server) handle(conn *Conn, messagesToSendClient <-chan interface{}) {
	var err error

	for {
		message := <-messagesToSendClient

		str, ok := message.(string)
		if ok {
			fmt.Fprintf(conn.out, str)
		} else {
			err = conn.SendStanza(message)
		}

		if err != nil {
			s.Log.Error(err.Error())
		}
	}
}
