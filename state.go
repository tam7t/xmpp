package xmpp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"strings"
)

// State processes the stream and moves to the next state
type State interface {
	Process(c *Connection, client *Client, s *Server) (State, error)
}

// NewTLSStateMachine return steps through TCP TLS state
func NewTLSStateMachine() State {
	normal := &Normal{}
	authedstream := &AuthedStream{Next: normal}
	authedstart := &AuthedStart{Next: authedstream}
	tlsauth := &TLSAuth{Next: authedstart}
	tlsstartstream := &TLSStartStream{Next: tlsauth}
	tlsupgrade := &TLSUpgrade{Next: tlsstartstream}
	firststream := &TLSUpgradeRequest{Next: tlsupgrade}
	start := &Start{Next: firststream}
	return start
}

// Start state
type Start struct {
	Next State
}

// Process message
func (state *Start) Process(c *Connection, client *Client, s *Server) (State, error) {
	_, err := c.Next()
	if err != nil {
		return nil, err
	}
	// TODO: check that se is a stream
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")
	return state.Next, nil
}

// TLSUpgradeRequest state
type TLSUpgradeRequest struct {
	Next State
}

// Process message
func (state *TLSUpgradeRequest) Process(c *Connection, client *Client, s *Server) (State, error) {
	_, err := c.Next()
	if err != nil {
		return nil, err
	}
	// TODO: ensure urn:ietf:params:xml:ns:xmpp-tls
	return state.Next, nil
}

// TLSUpgrade state
type TLSUpgrade struct {
	Next State
}

// Process message
func (state *TLSUpgrade) Process(c *Connection, client *Client, s *Server) (State, error) {
	c.SendRaw("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	// close the goroutines to free up the Raw socket
	c.Close()
	// perform the TLS handshake
	tlsConn := tls.Server(c.Raw, s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return nil, err
	}
	// restart the Connection
	c = NewConn(tlsConn, c.MessageTypes)
	return state.Next, nil
}

// TLSStartStream state
type TLSStartStream struct {
	Next State
}

// Process messages
func (state *TLSStartStream) Process(c *Connection, client *Client, s *Server) (State, error) {
	_, err := c.Next()
	if err != nil {
		return nil, err
	}
	// TODO: ensure check that se is a stream
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>")
	return state.Next, nil
}

// TLSAuth state
type TLSAuth struct {
	Next State
}

// Process messages
func (state *TLSAuth) Process(c *Connection, client *Client, s *Server) (State, error) {
	se, err := c.Next()
	if err != nil {
		return nil, err
	}
	// TODO: check what client sends, auth or register

	// read the full auth stanza
	_, val, err := c.Read(se)
	if err != nil {
		s.Log.Error(errors.New("Unable to read auth stanza").Error())
		return nil, err
	}
	switch v := val.(type) {
	case *saslAuth:
		data, err := base64.StdEncoding.DecodeString(v.Body)
		if err != nil {
			return nil, err
		}
		info := strings.Split(string(data), "\x00")
		// should check that info[1] starts with client.jid
		success, err := s.Accounts.Authenticate(info[1], info[2])
		if err != nil {
			return nil, err
		}
		if success {
			client.localpart = info[1]
			c.SendRaw("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
		} else {
			c.SendRaw("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")
		}
	default:
		// expected authentication
		s.Log.Error(errors.New("Expected authentication").Error())
		return nil, err
	}
	return state.Next, nil
}

// AuthedStart state
type AuthedStart struct {
	Next State
}

// Process messages
func (state *AuthedStart) Process(c *Connection, client *Client, s *Server) (State, error) {
	_, err := c.Next()
	if err != nil {
		return nil, err
	}
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>")
	return state.Next, nil
}

// AuthedStream state
type AuthedStream struct {
	Next State
}

// Process messages
func (state *AuthedStream) Process(c *Connection, client *Client, s *Server) (State, error) {
	se, err := c.Next()
	if err != nil {
		return nil, err
	}
	// check that it's a bind request
	// read bind request
	_, val, err := c.Read(se)
	if err != nil {
		return nil, err
	}
	switch v := val.(type) {
	case *ClientIQ:
		// TODO: actually validate that it's a bind request
		if v.Bind.Resource == "" {
			client.resourcepart = makeResource()
		} else {
			s.Log.Error(errors.New("Invalid bind request").Error())
			return nil, err
		}
		client.jid = client.localpart + "@" + client.domainpart + "/" + client.resourcepart
		c.SendRawf("<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", v.ID, client.jid)

		// fire off go routine to handle messages
		client.messages = make(chan interface{})
		s.ConnectBus <- Connect{Jid: client.jid, Receiver: client.messages}
	default:
		s.Log.Error(errors.New("Expected ClientIQ message").Error())
		return nil, err
	}
	return state.Next, nil
}

// Normal state
type Normal struct{}

// Process messages
func (state *Normal) Process(c *Connection, client *Client, s *Server) (State, error) {
	/* read from socket */
	se, err := c.Next()
	if err != nil {
		return nil, err
	}
	_, val, _ := c.Read(se)

	for _, extension := range s.Extensions {
		extension.Process(val, client)
	}
	return state, nil
}

// Closed state
type Closed struct{}

// Process messages
func (state *Closed) Process(c *Connection, client *Client, s *Server) (State, error) {
	close(client.messages)
	s.DisconnectBus <- Disconnect{Jid: client.jid}

	c.Raw.Close()

	return nil, nil
}
