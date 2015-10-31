package xmpp

import (
	"encoding/xml"
	"reflect"
)

const (
	// NsStream stream namesapce
	NsStream = "http://etherx.jabber.org/streams"
	// NsTLS xmpp-tls xml namespace
	NsTLS = "urn:ietf:params:xml:ns:xmpp-tls"
	// NsSASL xmpp-sasl xml namespace
	NsSASL = "urn:ietf:params:xml:ns:xmpp-sasl"
	// NsBind xmpp-bind xml namespace
	NsBind = "urn:ietf:params:xml:ns:xmpp-bind"
	// NsSession xmpp-session xml namespace
	NsSession = "urn:ietf:params:xml:ns:xmpp-session"
	// NsClient jabbet client namespace
	NsClient = "jabber:client"
)

// RFC 3920  C.1  Streams name space

// StreamError element
type StreamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name `xml:",any"`
	Text    string   `xml:"text"`
}

// RFC 3920  C.3  TLS name space

// tlsFailure element
type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

// RFC 3920  C.4  SASL name space

// saslMechanisms element
type saslMechanisms struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanism []string `xml:"mechanism"`
}

// saslAuth element
type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
	Body      string   `xml:",chardata"`
}

// RFC 3920  C.5  Resource binding name space

// bindBind element
type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource"`
	Jid      string   `xml:"jid"`
}

// XEP-0203: Delayed Delivery of <message/> and <presence/> stanzas.

// Delay element
type Delay struct {
	XMLName xml.Name `xml:"urn:xmpp:delay delay"`
	From    string   `xml:"from,attr,omitempty"`
	Stamp   string   `xml:"stamp,attr"`

	Body string `xml:",chardata"`
}

// RFC 3921  B.1  jabber:client

// ClientMessage element
type ClientMessage struct {
	XMLName xml.Name `xml:"jabber:client message"`
	From    string   `xml:"from,attr"`
	ID      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // chat, error, groupchat, headline, or normal

	// These should technically be []clientText,
	// but string is much more convenient.
	Subject string `xml:"subject"`
	Body    string `xml:"body"`
	Thread  string `xml:"thread"`
	Delay   *Delay `xml:"delay,omitempty"`
}

// ClientText element
type ClientText struct {
	Lang string `xml:"lang,attr"`
	Body string `xml:",chardata"`
}

// ClientPresence element
type ClientPresence struct {
	XMLName xml.Name `xml:"jabber:client presence"`
	From    string   `xml:"from,attr,omitempty"`
	ID      string   `xml:"id,attr,omitempty"`
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

// ClientCaps element
type ClientCaps struct {
	XMLName xml.Name `xml:"http://jabber.org/protocol/caps c"`
	Ext     string   `xml:"ext,attr"`
	Hash    string   `xml:"hash,attr"`
	Node    string   `xml:"node,attr"`
	Ver     string   `xml:"ver,attr"`
}

// ClientIQ element
type ClientIQ struct { // info/query
	XMLName xml.Name    `xml:"jabber:client iq"`
	From    string      `xml:"from,attr"`
	ID      string      `xml:"id,attr"`
	To      string      `xml:"to,attr"`
	Type    string      `xml:"type,attr"` // error, get, result, set
	Error   ClientError `xml:"error"`
	Bind    bindBind    `xml:"bind"`
	Query   []byte      `xml:",innerxml"`
	// RosterRequest - better detection of iq's
}

// ClientError element
type ClientError struct {
	XMLName xml.Name `xml:"jabber:client error"`
	Code    string   `xml:"code,attr"`
	Type    string   `xml:"type,attr"`
	Any     xml.Name `xml:",any"`
	Text    string   `xml:"text"`
}

// Roster element
type Roster struct {
	XMLName xml.Name      `xml:"jabber:iq:roster query"`
	Item    []RosterEntry `xml:"item"`
}

// RosterEntry element
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

// RosterRequestItem element
type RosterRequestItem struct {
	Jid          string   `xml:"jid,attr"`
	Subscription string   `xml:"subscription,attr"`
	Name         string   `xml:"name,attr"`
	Group        []string `xml:"group"`
}

// MessageTypes map of known message types
var MessageTypes = map[xml.Name]reflect.Type{
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
