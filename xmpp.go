// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	nsStream  = "http://etherx.jabber.org/streams"
	nsTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	nsSession = "urn:ietf:params:xml:ns:xmpp-session"
	nsClient  = "jabber:client"
)

// RemoveResourceFromJid returns the user@domain portion of a JID.
func RemoveResourceFromJid(jid string) string {
	slash := strings.Index(jid, "/")
	if slash != -1 {
		return jid[:slash]
	}
	return jid
}

// Conn represents a connection to an XMPP server.
type Conn struct {
	out        io.Writer
	rawOut     io.Writer // doesn't log. Used for <auth>
	in         *xml.Decoder
	jid        string
	nextCookie Cookie

	lock      sync.Mutex
	inflights map[Cookie]chan<- Stanza
}

// Stanza represents a message from the XMPP server.
type Stanza struct {
	Name  xml.Name
	Value interface{}
}

// Cookie is used to give a unique identifier to each request.
type Cookie uint64

func (c *Conn) getCookie() Cookie {
	ret := c.nextCookie
	c.nextCookie++
	return ret
}

// Next reads stanzas from the server. If the stanza is a reply, it dispatches
// it to the correct channel and reads the next message. Otherwise it returns
// the stanza for processing.
func (c *Conn) Next() (stanza Stanza, err error) {
	for {
		if stanza.Name, stanza.Value, err = next(c.in); err != nil {
			return
		}

		if iq, ok := stanza.Value.(*ClientIQ); ok && (iq.Type == "result" || iq.Type == "error") {
			var cookieValue uint64
			if cookieValue, err = strconv.ParseUint(iq.Id, 10, 64); err != nil {
				err = errors.New("xmpp: failed to parse id from iq: " + err.Error())
				return
			}
			cookie := Cookie(cookieValue)

			c.lock.Lock()
			ch, ok := c.inflights[cookie]
			if ok {
				delete(c.inflights, cookie)
			}
			c.lock.Unlock()

			if ok {
				ch <- stanza
			}
			continue
		}

		return
	}

	panic("unreachable")
}

// Cancel cancels and outstanding request. The request's channel is closed.
func (c *Conn) Cancel(cookie Cookie) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	ch, ok := c.inflights[cookie]
	if !ok {
		return false
	}

	delete(c.inflights, cookie)
	close(ch)
	return true
}

// RequestRoster requests the user's roster from the server. It returns a
// channel on which the reply can be read when received and a Cookie that can
// be used to cancel the request.
func (c *Conn) RequestRoster() (<-chan Stanza, Cookie, error) {
	cookie := c.getCookie()
	if _, err := fmt.Fprintf(c.out, "<iq type='get' id='%x'><query xmlns='jabber:iq:roster'/></iq>", cookie); err != nil {
		return nil, 0, err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	ch := make(chan Stanza, 1)
	c.inflights[cookie] = ch
	return ch, cookie, nil
}

// ParseRoster extracts roster information from the given Stanza.
func ParseRoster(reply Stanza) ([]RosterEntry, error) {
	iq, ok := reply.Value.(*ClientIQ)
	if !ok {
		return nil, errors.New("xmpp: roster request resulted in tag of type " + reply.Name.Local)
	}

	var roster Roster
	if err := xml.NewDecoder(bytes.NewBuffer(iq.Query)).Decode(&roster); err != nil {
		return nil, err
	}
	return roster.Item, nil
}

// SendIQ sends an info/query message to the given user. It returns a channel
// on which the reply can be read when received and a Cookie that can be used
// to cancel the request.
func (c *Conn) SendIQ(to, typ string, value interface{}) (reply chan Stanza, cookie Cookie, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	cookie = c.getCookie()
	reply = make(chan Stanza, 1)

	toAttr := ""
	if len(to) > 0 {
		toAttr = "to='" + xmlEscape(to) + "'"
	}
	if _, err = fmt.Fprintf(c.out, "<iq %s from='%s' type='%s' id='%d'>", toAttr, xmlEscape(c.jid), xmlEscape(typ), cookie); err != nil {
		return
	}
	if _, ok := value.(EmptyReply); !ok {
		if err = xml.NewEncoder(c.out).Encode(value); err != nil {
			return
		}
	}
	if _, err = fmt.Fprintf(c.out, "</iq>"); err != nil {
		return
	}

	c.inflights[cookie] = reply
	return
}

// SendIQReply sends a reply to an IQ query.
func (c *Conn) SendIQReply(to, typ, id string, value interface{}) error {
	if _, err := fmt.Fprintf(c.out, "<iq to='%s' from='%s' type='%s' id='%s'>", xmlEscape(to), xmlEscape(c.jid), xmlEscape(typ), xmlEscape(id)); err != nil {
		return err
	}
	if _, ok := value.(EmptyReply); !ok {
		if err := xml.NewEncoder(c.out).Encode(value); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(c.out, "</iq>")
	return err
}

// Send sends an IM message to the given user.
func (c *Conn) Send(to, msg string) error {
	_, err := fmt.Fprintf(c.out, "<message to='%s' from='%s' type='chat'><body>%s</body></message>", xmlEscape(to), xmlEscape(c.jid), xmlEscape(msg))
	return err
}

// SendPresence sends a presence stanza. If id is empty, a unique id is
// generated.
func (c *Conn) SendPresence(to, typ, id string) error {
	if len(id) == 0 {
		id = strconv.FormatUint(uint64(c.getCookie()), 10)
	}
	_, err := fmt.Fprintf(c.out, "<presence id='%s' to='%s' type='%s'/>", xmlEscape(id), xmlEscape(to), xmlEscape(typ))
	return err
}

func (c *Conn) SignalPresence(state string) error {
	_, err := fmt.Fprintf(c.out, "<presence><show>%s</show></presence>", xmlEscape(state))
	return err
}

// rfc3920 section 5.2
func (c *Conn) getFeatures(domain string) (features streamFeatures, err error) {
	if _, err = fmt.Fprintf(c.out, "<?xml version='1.0'?><stream:stream to='%s' xmlns='%s' xmlns:stream='%s' version='1.0'>\n", xmlEscape(domain), nsClient, nsStream); err != nil {
		return
	}

	se, err := nextStart(c.in)
	if err != nil {
		return
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		err = errors.New("xmpp: expected <stream> but got <" + se.Name.Local + "> in " + se.Name.Space)
		return
	}

	// Now we're in the stream and can use Unmarshal.
	// Next message should be <features> to tell us authentication options.
	// See section 4.6 in RFC 3920.
	if err = c.in.DecodeElement(&features, nil); err != nil {
		err = errors.New("unmarshal <features>: " + err.Error())
		return
	}

	return
}

func (c *Conn) authenticate(features streamFeatures, user, password string) (err error) {
	havePlain := false
	for _, m := range features.Mechanisms.Mechanism {
		if m == "PLAIN" {
			havePlain = true
			break
		}
	}
	if !havePlain {
		return errors.New("xmpp: PLAIN authentication is not an option")
	}

	// Plain authentication: send base64-encoded \x00 user \x00 password.
	raw := "\x00" + user + "\x00" + password
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, []byte(raw))
	fmt.Fprintf(c.rawOut, "<auth xmlns='%s' mechanism='PLAIN'>%s</auth>\n", nsSASL, enc)

	// Next message should be either success or failure.
	name, val, err := next(c.in)
	switch v := val.(type) {
	case *saslSuccess:
	case *saslFailure:
		// v.Any is type of sub-element in failure,
		// which gives a description of what failed.
		return errors.New("xmpp: authentication failure: " + v.Any.Local)
	default:
		return errors.New("expected <success> or <failure>, got <" + name.Local + "> in " + name.Space)
	}

	return nil
}

func certName(cert *x509.Certificate) string {
	name := cert.Subject
	ret := ""

	for _, org := range name.Organization {
		ret += "O=" + org + "/"
	}
	for _, ou := range name.OrganizationalUnit {
		ret += "OU=" + ou + "/"
	}
	if len(name.CommonName) > 0 {
		ret += "CN=" + name.CommonName + "/"
	}
	return ret
}

// Resolve performs a DNS SRV lookup for the XMPP server that serves the given
// domain.
func Resolve(domain string) (host string, port uint16, err error) {
	_, addrs, err := net.LookupSRV("xmpp-client", "tcp", domain)
	if err != nil {
		return "", 0, err
	}
	if len(addrs) == 0 {
		return "", 0, errors.New("xmpp: no SRV records found for " + domain)
	}

	return addrs[0].Target, addrs[0].Port, nil
}

// Config contains options for an XMPP connection.
type Config struct {
	// Conn is the connection to the server, if non-nill.
	Conn net.Conn
	// InLog is an optional Writer which receives the raw contents of the
	// XML from the server.
	InLog io.Writer
	// OutLog is an option Writer which receives the raw XML sent to the
	// server.
	OutLog io.Writer
	// Log is an optional Writer which receives human readable log messages
	// during the connection.
	Log io.Writer
	// Create, if true, causes a new account to be created on the server.
	Create bool
	// TrustedAddress, if true, means that the address passed to Dial is
	// trusted and that certificates for that name should be accepted.
	TrustedAddress bool
}

// Dial creates a new connection to an XMPP server and authenticates as the
// given user.
func Dial(address, user, domain, password string, config *Config) (c *Conn, err error) {
	c = new(Conn)
	c.inflights = make(map[Cookie]chan<- Stanza)

	var log io.Writer
	if config != nil && config.Log != nil {
		log = config.Log
	}

	var conn net.Conn
	if config != nil && config.Conn != nil {
		conn = config.Conn
	} else {
		if log != nil {
			io.WriteString(log, "Making TCP connection to "+address+"\n")
		}

		if conn, err = net.Dial("tcp", address); err != nil {
			return nil, err
		}
	}

	c.in, c.out = makeInOut(conn, config)

	features, err := c.getFeatures(domain)
	if err != nil {
		return nil, err
	}

	if features.StartTLS.XMLName.Local == "" {
		return nil, errors.New("xmpp: server doesn't support TLS")
	}

	fmt.Fprintf(c.out, "<starttls xmlns='%s'/>", nsTLS)

	proceed, err := nextStart(c.in)
	if err != nil {
		return nil, err
	}
	if proceed.Name.Space != nsTLS || proceed.Name.Local != "proceed" {
		return nil, errors.New("xmpp: expected <proceed> after <starttls> but got <" + proceed.Name.Local + "> in " + proceed.Name.Space)
	}

	if log != nil {
		io.WriteString(log, "Starting TLS handshake\n")
	}

	tlsConn := tls.Client(conn, nil)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	tlsState := tlsConn.ConnectionState()
	if len(tlsState.VerifiedChains) == 0 {
		return nil, errors.New("xmpp: failed to verify TLS certificate")
	}

	if log != nil {
		for i, cert := range tlsState.VerifiedChains[0] {
			fmt.Fprintf(log, "  certificate %d: %s\n", i, certName(cert))
		}
	}

	if err := tlsConn.VerifyHostname(domain); err != nil {
		if config.TrustedAddress {
			if log != nil {
				fmt.Fprintf(log, "Certificate fails to verify against domain in username: %s\n", err)
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("xmpp: failed to split address when checking whether TLS certificate is valid: " + err.Error())
			}
			if err = tlsConn.VerifyHostname(host); err != nil {
				return nil, errors.New("xmpp: failed to match TLS certificate to address after failing to match to username: " + err.Error())
			}
			if log != nil {
				fmt.Fprintf(log, "Certificate matches against trusted server hostname: %s\n", host)
			}
		} else {
			return nil, errors.New("xmpp: failed to match TLS certificate to name: " + err.Error())
		}
	}

	c.in, c.out = makeInOut(tlsConn, config)
	c.rawOut = tlsConn

	if features, err = c.getFeatures(domain); err != nil {
		return nil, err
	}

	if config != nil && config.Create {
		if log != nil {
			io.WriteString(log, "Attempting to create account\n")
		}
		fmt.Fprintf(c.rawOut, "<iq type='set' id='create_1'><query xmlns='jabber:iq:register'><username>%s</username><password>%s</password></query></iq>", user, password)
		var iq ClientIQ
		if err = c.in.DecodeElement(&iq, nil); err != nil {
			return nil, errors.New("unmarshal <iq>: " + err.Error())
		}
		if iq.Type == "error" {
			return nil, errors.New("xmpp: account creation failed")
		}
	}

	if log != nil {
		io.WriteString(log, "Authenticating as "+user+"\n")
	}
	if err := c.authenticate(features, user, password); err != nil {
		return nil, err
	}

	if log != nil {
		io.WriteString(log, "Authentication successful\n")
	}

	if features, err = c.getFeatures(domain); err != nil {
		return nil, err
	}

	// Send IQ message asking to bind to the local user name.
	fmt.Fprintf(c.out, "<iq type='set' id='bind_1'><bind xmlns='%s'/></iq>", nsBind)
	var iq ClientIQ
	if err = c.in.DecodeElement(&iq, nil); err != nil {
		return nil, errors.New("unmarshal <iq>: " + err.Error())
	}
	if &iq.Bind == nil {
		return nil, errors.New("<iq> result missing <bind>")
	}
	c.jid = iq.Bind.Jid // our local id

	if features.Session != nil {
		// The server needs a session to be established. See RFC 3921,
		// section 3.
		fmt.Fprintf(c.out, "<iq to='%s' type='set' id='sess_1'><session xmlns='%s'/></iq>", domain, nsSession)
		if err = c.in.DecodeElement(&iq, nil); err != nil {
			return nil, errors.New("xmpp: unmarshal <iq>: " + err.Error())
		}
		if iq.Type != "result" {
			return nil, errors.New("xmpp: session establishment failed")
		}
	}

	return c, nil
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
func nextStart(p *xml.Decoder) (elem xml.StartElement, err error) {
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

type streamFeatures struct {
	XMLName    xml.Name `xml:"http://etherx.jabber.org/streams features"`
	StartTLS   tlsStartTLS
	Mechanisms saslMechanisms
	Bind       bindBind
	// This is a hack for now to get around the fact that the new encoding/xml
	// doesn't unmarshal to XMLName elements.
	Session *string `xml:"session"`
}

type streamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name `xml:",any"`
	Text    string   `xml:"text"`
}

// RFC 3920  C.3  TLS name space

type tlsStartTLS struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`
	Required xml.Name `xml:"required"`
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

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
}

type saslChallenge string

type saslResponse string

type saslAbort struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

type saslSuccess struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl success"`
}

type saslFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Any     xml.Name `xml:",any"`
}

// RFC 3920  C.5  Resource binding name space

type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource"`
	Jid      string   `xml:"jid"`
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
}

type ClientText struct {
	Lang string `xml:"lang,attr"`
	Body string `xml:",chardata"`
}

type ClientPresence struct {
	XMLName xml.Name `xml:"jabber:client presence"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // error, probe, subscribe, subscribed, unavailable, unsubscribe, unsubscribed
	Lang    string   `xml:"lang,attr"`

	Show     string       `xml:"show"`   // away, chat, dnd, xa
	Status   string       `xml:"status"` // sb []clientText
	Priority string       `xml:"priority"`
	Error    *ClientError `xml:"error"`
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

// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func next(p *xml.Decoder) (xml.Name, interface{}, error) {
	// Read start element to find out what type we want.
	se, err := nextStart(p)
	if err != nil {
		return xml.Name{}, nil, err
	}

	// Put it in an interface and allocate one.
	var nv interface{}
	switch se.Name.Space + " " + se.Name.Local {
	case nsStream + " features":
		nv = &streamFeatures{}
	case nsStream + " error":
		nv = &streamError{}
	case nsTLS + " starttls":
		nv = &tlsStartTLS{}
	case nsTLS + " proceed":
		nv = &tlsProceed{}
	case nsTLS + " failure":
		nv = &tlsFailure{}
	case nsSASL + " mechanisms":
		nv = &saslMechanisms{}
	case nsSASL + " challenge":
		nv = ""
	case nsSASL + " response":
		nv = ""
	case nsSASL + " abort":
		nv = &saslAbort{}
	case nsSASL + " success":
		nv = &saslSuccess{}
	case nsSASL + " failure":
		nv = &saslFailure{}
	case nsBind + " bind":
		nv = &bindBind{}
	case nsClient + " message":
		nv = &ClientMessage{}
	case nsClient + " presence":
		nv = &ClientPresence{}
	case nsClient + " iq":
		nv = &ClientIQ{}
	case nsClient + " error":
		nv = &ClientError{}
	default:
		return xml.Name{}, nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = p.DecodeElement(nv, &se); err != nil {
		return xml.Name{}, nil, err
	}
	return se.Name, nv, err
}

type DiscoveryReply struct {
	XMLName    xml.Name `xml:"http://jabber.org/protocol/disco#info query"`
	Identities []DiscoveryIdentity
	Features   []DiscoveryFeature
}

type DiscoveryIdentity struct {
	XMLName  xml.Name `xml:"http://jabber.org/protocol/disco#info identity"`
	Category string   `xml:"category,attr"`
	Type     string   `xml:"type,attr"`
	Name     string   `xml:"name,attr"`
}

type DiscoveryFeature struct {
	XMLName xml.Name `xml:"http://jabber.org/protocol/disco#info feature"`
	Var     string   `xml:"var,attr"`
}

type VersionQuery struct {
	XMLName xml.Name `xml:"jabber:iq:version query"`
}

type VersionReply struct {
	XMLName xml.Name `xml:"jabber:iq:version query"`
	Name    string   `xml:"name"`
	Version string   `xml:"version"`
	OS      string   `xml:"os"`
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

// An EmptyReply results in in no XML.
type EmptyReply struct {
}
