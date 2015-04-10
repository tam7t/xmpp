// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
)

const (
	NsStream  = "http://etherx.jabber.org/streams"
	NsTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	NsSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	NsBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	NsSession = "urn:ietf:params:xml:ns:xmpp-session"
	NsClient  = "jabber:client"
)

// RemoveResourceFromJid returns the user@domain portion of a JID.
func RemoveResourceFromJid(jid string) string {
	slash := strings.Index(jid, "/")
	if slash != -1 {
		return jid[:slash]
	}
	return jid
}

// domainFromJid returns the domain of a full or bare JID.
func domainFromJid(jid string) string {
	jid = RemoveResourceFromJid(jid)
	at := strings.Index(jid, "@")
	if at != -1 {
		return jid[at+1:]
	}
	return jid
}

const (
	STATE_INIT = iota
	STATE_FIRST_STREAM
	STATE_TLS_UPGRADE_REQUESTED
	STATE_TLS_UPGRADED
	STATE_TLS_START_STREAM
	STATE_TLS_AUTH
	STATE_TLS_REGISTER
	STATE_AUTHED_START
	STATE_AUTHED_STREAM
	STATE_BINDED_STREAM
	STATE_NORMAL
	STATE_ERROR
	STATE_CLOSED
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

// Cookie is used to give a unique identifier to each request.
type Cookie uint64

func (c *Conn) getCookie() Cookie {
	var buf [8]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return Cookie(binary.LittleEndian.Uint64(buf[:]))
}

func makeResource() string {
	var buf [16]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return fmt.Sprintf("%x", buf)
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

var tlsVersionStrings = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
}

var tlsCipherSuiteNames = map[uint16]string{
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
}

func makeInOut(conn io.ReadWriter) (in *xml.Decoder, out io.Writer) {
	in = xml.NewDecoder(conn)
	out = conn
	return
}

// Scan XML token stream to find next StartElement.
func nextStart(c *Conn) (elem xml.StartElement, err error) {
	var p *xml.Decoder
	p = c.in
	for {
		var t xml.Token
		t, err = p.Token()
		if err != nil {
			return
		}
		switch t := t.(type) {
		case xml.StartElement:
			elem = t
			return
		}
	}
	panic("unreachable")
}

// RFC 3920  C.1  Streams name space

type StreamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name `xml:",any"`
	Text    string   `xml:"text"`
}

// RFC 3920  C.3  TLS name space

type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

// RFC 3920  C.4  SASL name space

type saslMechanisms struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanism []string `xml:"mechanism"`
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
	Body      string   `xml:",chardata"`
}

// RFC 3920  C.5  Resource binding name space

type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource"`
	Jid      string   `xml:"jid"`
}

// XEP-0203: Delayed Delivery of <message/> and <presence/> stanzas.
type Delay struct {
	XMLName xml.Name `xml:"urn:xmpp:delay delay"`
	From    string   `xml:"from,attr,omitempty"`
	Stamp   string   `xml:"stamp,attr"`

	Body string `xml:",chardata"`
}

// RFC 3921  B.1  jabber:client
type ClientMessage struct {
	XMLName xml.Name `xml:"jabber:client message"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // chat, error, groupchat, headline, or normal

	// These should technically be []clientText,
	// but string is much more convenient.
	Subject string `xml:"subject"`
	Body    string `xml:"body"`
	Thread  string `xml:"thread"`
	Delay   *Delay `xml:"delay,omitempty"`
}

type ClientText struct {
	Lang string `xml:"lang,attr"`
	Body string `xml:",chardata"`
}

type ClientPresence struct {
	XMLName xml.Name `xml:"jabber:client presence"`
	From    string   `xml:"from,attr,omitempty"`
	Id      string   `xml:"id,attr,omitempty"`
	To      string   `xml:"to,attr,omitempty"`
	Type    string   `xml:"type,attr,omitempty"` // error, probe, subscribe, subscribed, unavailable, unsubscribe, unsubscribed
	Lang    string   `xml:"lang,attr,omitempty"`

	Show     string       `xml:"show,omitempty"`   // away, chat, dnd, xa
	Status   string       `xml:"status,omitempty"` // sb []clientText
	Priority string       `xml:"priority,omitempty"`
	Caps     *ClientCaps  `xml:"c"`
	Error    *ClientError `xml:"error"`
	Delay    Delay        `xml:"delay"`
}

type ClientCaps struct {
	XMLName xml.Name `xml:"http://jabber.org/protocol/caps c"`
	Ext     string   `xml:"ext,attr"`
	Hash    string   `xml:"hash,attr"`
	Node    string   `xml:"node,attr"`
	Ver     string   `xml:"ver,attr"`
}

type ClientIQ struct { // info/query
	XMLName xml.Name    `xml:"jabber:client iq"`
	From    string      `xml:"from,attr"`
	Id      string      `xml:"id,attr"`
	To      string      `xml:"to,attr"`
	Type    string      `xml:"type,attr"` // error, get, result, set
	Error   ClientError `xml:"error"`
	Bind    bindBind    `xml:"bind"`
	Query   []byte      `xml:",innerxml"`
	// RosterRequest - better detection of iq's
}

type ClientError struct {
	XMLName xml.Name `xml:"jabber:client error"`
	Code    string   `xml:"code,attr"`
	Type    string   `xml:"type,attr"`
	Any     xml.Name `xml:",any"`
	Text    string   `xml:"text"`
}

type Roster struct {
	XMLName xml.Name      `xml:"jabber:iq:roster query"`
	Item    []RosterEntry `xml:"item"`
}

type RosterEntry struct {
	Jid          string   `xml:"jid,attr"`
	Subscription string   `xml:"subscription,attr"`
	Name         string   `xml:"name,attr"`
	Group        []string `xml:"group"`
}

type RoutableMessage struct {
	To   string
	Data interface{}
}

// http://www.xmpp.org/extensions/xep-0077.html
// <feature var='jabber:iq:register'/>
// this would occur after TLS but before authentication

// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func next(c *Conn, se xml.StartElement) (xml.Name, interface{}, error) {
	// Put start element in an interface and allocate one.
	var nv interface{}
	var err error
	if t, e := defaultStorage[se.Name]; e {
		nv = reflect.New(t).Interface()
	} else {
		return xml.Name{}, nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = c.in.DecodeElement(nv, &se); err != nil {
		return xml.Name{}, nil, err
	}
	return se.Name, nv, err
}

var defaultStorage = map[xml.Name]reflect.Type{
	xml.Name{Space: NsStream, Local: "error"}:    reflect.TypeOf(StreamError{}),
	xml.Name{Space: NsTLS, Local: "failure"}:     reflect.TypeOf(tlsFailure{}),
	xml.Name{Space: NsSASL, Local: "auth"}:       reflect.TypeOf(saslAuth{}),
	xml.Name{Space: NsSASL, Local: "mechanisms"}: reflect.TypeOf(saslMechanisms{}),
	xml.Name{Space: NsSASL, Local: "challenge"}:  reflect.TypeOf(""),
	xml.Name{Space: NsSASL, Local: "response"}:   reflect.TypeOf(""),
	xml.Name{Space: NsBind, Local: "bind"}:       reflect.TypeOf(bindBind{}),
	xml.Name{Space: NsClient, Local: "message"}:  reflect.TypeOf(ClientMessage{}),
	xml.Name{Space: NsClient, Local: "presence"}: reflect.TypeOf(ClientPresence{}),
	xml.Name{Space: NsClient, Local: "iq"}:       reflect.TypeOf(ClientIQ{}),
	xml.Name{Space: NsClient, Local: "error"}:    reflect.TypeOf(ClientError{}),
}

// RosterRequest is used to request that the server update the user's roster.
// See RFC 6121, section 2.3.
type RosterRequest struct {
	XMLName xml.Name          `xml:"jabber:iq:roster query"`
	Item    RosterRequestItem `xml:"item"`
}

type RosterRequestItem struct {
	Jid          string   `xml:"jid,attr"`
	Subscription string   `xml:"subscription,attr"`
	Name         string   `xml:"name,attr"`
	Group        []string `xml:"group"`
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
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", c.getCookie())
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
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", c.getCookie())
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
			fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", c.getCookie())
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
