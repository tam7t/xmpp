// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"reflect"
	"strings"
	"sync"
	"os"
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
	STATE_INIT                  = iota
	STATE_FIRST_STREAM          = iota
	STATE_TLS_UPGRADE_REQUESTED = iota
	STATE_TLS_UPGRADED          = iota
	STATE_TLS_START_STREAM      = iota
	STATE_TLS_AUTH              = iota
	STATE_TLS_REGISTER          = iota
	STATE_AUTHED_START          = iota
	STATE_AUTHED_STREAM         = iota
	STATE_BINDED_STREAM         = iota
	STATE_NORMAL                = iota
	STATE_ERROR                 = iota
	STATE_CLOSED                = iota
)

// Conn represents a connection to an XMPP server.
type Conn struct {
	out          io.Writer
	rawOut       io.Writer // doesn't log. Used for <auth>
	in           *xml.Decoder
	jid          string
	localpart    string
	domainpart   string
	resourcepart string
	lock         sync.Mutex
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

func (c *Conn) SendStanza(s interface{}) error {
	return xml.NewEncoder(c.out).Encode(s)
}

type AccountCallback func(username, password string) (success bool, err error)

type MessageCallback func(jid string, messagesToSendClient chan<- interface{})

type RosterCallback func(jid string) (online []string)

// Config contains options for an XMPP connection.
type Config struct {
	// Conn is the connection to the server, if non-nill.
	Conn net.Conn
	// InLog is an optional Writer which receives the raw contents of the
	// XML from the server.
	InLog io.Writer
	// OutLog is an optional Writer which receives the raw XML sent to the
	// server.
	OutLog io.Writer
	// Log is an optional Writer which receives human readable log messages
	// during the connection.
	Log io.Writer

	// Authentication Callback
	AuthenticateAccountCallback AccountCallback
	// Create Account Channel
	CreateAccountCallback AccountCallback
	// register inboudn callback
	RegisterInboundMessages MessageCallback
	// returns the user's roster as []string
	UserRosterCallback RosterCallback

	OnlineMap map[string](*Conn)
	// what domain to use?
	Domain string

	// SkipTLS, if true, causes the TLS handshake to be skipped.
	// WARNING: this should only be used if Conn is already secure.
	SkipTLS bool
	// TLSConfig contains the configuration to be used by the TLS
	// handshake. If nil, sensible defaults will be used.
	TLSConfig *tls.Config
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

func makeInOut(conn io.ReadWriter, config *Config) (in *xml.Decoder, out io.Writer) {
	if config != nil && config.InLog != nil {
		in = xml.NewDecoder(io.TeeReader(conn, config.InLog))
	} else {
		in = xml.NewDecoder(conn)
	}

	if config != nil && config.OutLog != nil {
		out = io.MultiWriter(conn, config.OutLog)
	} else {
		out = conn
	}

	return
}

var xmlSpecial = map[byte]string{
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&apos;",
	'&':  "&amp;",
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if s, ok := xmlSpecial[c]; ok {
			b.WriteString(s)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
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
	To 			string
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

// ErrorReply reflects an XMPP error stanza. See
// http://xmpp.org/rfcs/rfc6120.html#stanzas-error-syntax
type ErrorReply struct {
	XMLName xml.Name    `xml:"error"`
	Type    string      `xml:"type,attr"`
	Error   interface{} `xml:"error"`
}

// ErrorBadRequest reflects a bad-request stanza. See
// http://xmpp.org/rfcs/rfc6120.html#stanzas-error-conditions-bad-request
type ErrorBadRequest struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-stanzas bad-request"`
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

	log := ioutil.Discard
	if config != nil && config.Log != nil {
		log = config.Log
	}

	fmt.Fprintf(log, "start")

	c.in, c.out = makeInOut(conn, config)
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
			c.in, c.out = makeInOut(tlsConn, config)
			c.rawOut = tlsConn
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
				success, err := config.AuthenticateAccountCallback(info[1], info[2])
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
				fmt.Fprintf(log, "%s", err.Error())
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
				fmt.Fprintf(log, "%s", err.Error())
				panic("bad * state")
			}
			switch v := val.(type) {
			case *ClientIQ:
				// TODO: actually validate that it's a bind request
				if v.Bind.Resource == "" {
					c.resourcepart = uuid.New()
				} else {
					panic("ahhh")
				}
				c.jid = c.localpart + "@" + c.domainpart + "/" + c.resourcepart
				fmt.Fprintf(c.out, "<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", v.Id, c.jid)
				// fire off go routine to handle messages
				messagesToSendClient = make(chan interface{})
				go handle(c, messagesToSendClient)
				config.RegisterInboundMessages(c.jid, messagesToSendClient)
				c.state = STATE_NORMAL
			default:
				panic("even worse!")
			}
		case STATE_NORMAL:
			/* read from socket */
			se, err = nextStart(c)
			if err != nil {
				fmt.Fprintf(log, "could not read %s\n", err.Error())
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
			    roster := config.UserRosterCallback(c.jid)
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
				fmt.Fprintf(log, "UNKNOWN STANZA %s\n", val)
				// panic("unknown stanza")
			}
		case STATE_ERROR:
			s.state = STATE_CLOSED
		case STATE_CLOSED:
			fmt.Fprintf(log, "error state")
			close(messagesToSendClient)
			conn.Close()
			break
		}
	}
}

func make_message(message string) (value interface{}) {
	err := xml.Unmarshal([]byte(message), &value)
	if err != nil {
		panic("unable to encode data")
	}
	return
}

func handle(conn *Conn, messagesToSendClient <-chan interface{}) {
	var err error

	for {
		message := <- messagesToSendClient

		str, ok := message.(string)
		if ok {
			fmt.Fprintf(conn.out, str)
		} else {
		    err = conn.SendStanza(message)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s \n", err.Error())
			break
		}
	}
}
