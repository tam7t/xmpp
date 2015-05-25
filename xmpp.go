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
}

type MessageRouter interface {
	// register a channel for server to send JID messages
	RegisterClient(jid string, publish chan<- interface{}) error
	OnlineRoster(jid string) (online []string, err error)
}

type Logging interface {
	Debug(string) error
	Info(string) error
	Error(string) error
}

// Config contains options for an XMPP connection.
type Config struct {
	// what domain to use?
	Domain string

	// SkipTLS, if true, causes the TLS handshake to be skipped.
	// WARNING: this should only be used if Conn is already secure.
	SkipTLS bool
	// TLSConfig contains the configuration to be used by the TLS
	// handshake. If nil, sensible defaults will be used.
	TLSConfig *tls.Config

	// Injectable Account Manager
	Accounts AccountManager
	// Injectable Message Router
	Router MessageRouter
	// Injectable logging interface
	Log Logging
}

func makeInOut(conn io.ReadWriter) (in *xml.Decoder, out io.Writer) {
	in = xml.NewDecoder(conn)
	out = conn
	return
}

type RoutableMessage struct {
	To   string
	Data interface{}
}

func TcpAnswer(conn net.Conn, messageBus chan<- RoutableMessage, config *Config) (err error) {
	var c = new(Conn)
	var se xml.StartElement
	var val interface{}
	var messagesToSendClient chan interface{}

	c.state = STATE_INIT

	log := config.Log
	log.Info("start")

	c.in, c.out = makeInOut(conn)
	c.domainpart = config.Domain

	for {
		switch c.state {
		case STATE_INIT:
			se, err = nextStart(c)
			if err != nil {
				panic("bad state")
			}
			// TODO: check that se is a stream
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")
			c.state = STATE_FIRST_STREAM
		case STATE_FIRST_STREAM:
			se, err = nextStart(c)
			if err != nil {
				panic("bad state")
			}
			// TODO: ensure urn:ietf:params:xml:ns:xmpp-tls
			c.state = STATE_TLS_UPGRADE_REQUESTED
		case STATE_TLS_UPGRADE_REQUESTED:
			fmt.Fprintf(c.out, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
			tlsConn := tls.Server(conn, config.TLSConfig)
			tlsConn.Handshake()
			c.in, c.out = makeInOut(tlsConn)
			c.state = STATE_TLS_UPGRADED
		case STATE_TLS_UPGRADED:
			se, err = nextStart(c)
			if err != nil {
				panic("bad state")
			}
			// TODO: ensure check that se is a stream
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>")
			c.state = STATE_TLS_START_STREAM
		case STATE_TLS_START_STREAM:
			se, err = nextStart(c)
			if err != nil {
				panic("bad state")
			}
			// TODO: check what client sends, auth or register
			c.state = STATE_TLS_AUTH
		case STATE_TLS_AUTH:
			// read the full auth stanza
			_, val, err = next(c, se)
			if err != nil {
				panic("bad state")
			}
			switch v := val.(type) {
			case *saslAuth:
				data, err := base64.StdEncoding.DecodeString(v.Body)
				if err != nil {
					c.state = STATE_ERROR
				}
				s := string(data)
				info := strings.Split(s, "\x00")
				// should check that info[1] starts with client.jid
				success, err := config.Accounts.Authenticate(info[1], info[2])
				if err != nil {
					panic("bad authentate account callback")
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
				c.state = STATE_ERROR
			}
		case STATE_TLS_REGISTER:
			panic("registration not implemented")
		case STATE_AUTHED_START:
			se, err = nextStart(c)
			if err != nil {
				log.Error(fmt.Sprintf("%s", err.Error()))
				panic("bad state--")
			}
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
			fmt.Fprintf(c.out, "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>")
			c.state = STATE_AUTHED_STREAM
		case STATE_AUTHED_STREAM:
			se, err = nextStart(c)
			if err != nil {
				panic("bad state?")
			}
			// check that it's a bind request
			// read bind request
			_, val, err := next(c, se)
			if err != nil {
				log.Error(fmt.Sprintf("%s", err.Error()))
				panic("bad * state")
			}
			switch v := val.(type) {
			case *ClientIQ:
				// TODO: actually validate that it's a bind request
				if v.Bind.Resource == "" {
					c.resourcepart = makeResource()
				} else {
					panic("ahhh")
				}
				c.jid = c.localpart + "@" + c.domainpart + "/" + c.resourcepart
				fmt.Fprintf(c.out, "<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", v.Id, c.jid)

				// fire off go routine to handle messages
				messagesToSendClient = make(chan interface{})
				go handle(c, messagesToSendClient)
				config.Router.RegisterClient(c.jid, messagesToSendClient)

				c.state = STATE_NORMAL
			default:
				panic("even worse!")
			}
		case STATE_NORMAL:
			/* read from socket */
			se, err = nextStart(c)
			if err != nil {
				log.Error(fmt.Sprintf("could not read %s\n", err.Error()))
				panic("bad - state")
			}
			_, val, _ = next(c, se)
			switch v := val.(type) {
			case *ClientMessage:
				messageBus <- RoutableMessage{To: v.To, Data: val}
			case *ClientIQ:
				// handle things we need to handle
				if string(v.Query) == "<query xmlns='jabber:iq:roster'/>" {
					// respond with roster
					roster, _ := config.Router.OnlineRoster(c.jid)
					msg := "<iq id='" + v.Id + "' to='" + v.From + "' type='result'><query xmlns='jabber:iq:roster' ver='ver7'>"
					for _, v := range roster {
						msg = msg + "<item jid='" + v + "'/>"
					}
					msg = msg + "</query></iq>"

					messagesToSendClient <- msg
				} else {
					messageBus <- RoutableMessage{To: v.To, Data: val}
				}
			default:
				log.Error(fmt.Sprintf("UNKNOWN STANZA %s\n", val))
			}
		case STATE_ERROR:
			c.state = STATE_CLOSED
		case STATE_CLOSED:
			log.Error("error state")
			close(messagesToSendClient)
			conn.Close()
			break
		}
	}
}

func handle(conn *Conn, messagesToSendClient <-chan interface{}) {
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
			break
		}
	}
}
