package xmpp

import (
	"encoding/xml"
	"errors"
	"reflect"
)

const (
	NsStream  = "http://etherx.jabber.org/streams"
	NsTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	NsSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	NsBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	NsSession = "urn:ietf:params:xml:ns:xmpp-session"
	NsClient  = "jabber:client"
)

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
