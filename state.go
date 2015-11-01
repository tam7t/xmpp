package xmpp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// State processes the stream and moves to the next state
type State interface {
	Process(c *Connection, client *Client, s *Server) (State, *Connection, error)
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
func (state *Start) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	_, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	// TODO: check that se is a stream
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>")
	return state.Next, c, nil
}

// TLSUpgradeRequest state
type TLSUpgradeRequest struct {
	Next State
}

// Process message
func (state *TLSUpgradeRequest) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	_, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	// TODO: ensure urn:ietf:params:xml:ns:xmpp-tls
	return state.Next, c, nil
}

// TLSUpgrade state
type TLSUpgrade struct {
	Next State
}

// Process message
func (state *TLSUpgrade) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	c.SendRaw("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	// perform the TLS handshake
	tlsConn := tls.Server(c.Raw, s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return nil, c, err
	}
	// restart the Connection
	c = NewConn(tlsConn, c.MessageTypes)
	return state.Next, c, nil
}

// TLSStartStream state
type TLSStartStream struct {
	Next State
}

// Process messages
func (state *TLSStartStream) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	_, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	// TODO: ensure check that se is a stream
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>")
	return state.Next, c, nil
}

// TLSAuth state
type TLSAuth struct {
	Next State
}

// Process messages
func (state *TLSAuth) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	se, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	// TODO: check what client sends, auth or register

	// read the full auth stanza
	_, val, err := c.Read(se)
	if err != nil {
		s.Log.Error(errors.New("Unable to read auth stanza").Error())
		return nil, c, err
	}
	switch v := val.(type) {
	case *saslAuth:
		data, err := base64.StdEncoding.DecodeString(v.Body)
		if err != nil {
			return nil, c, err
		}
		info := strings.Split(string(data), "\x00")
		// should check that info[1] starts with client.jid
		success, err := s.Accounts.Authenticate(info[1], info[2])
		if err != nil {
			return nil, c, err
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
		return nil, c, err
	}
	return state.Next, c, nil
}

// AuthedStart state
type AuthedStart struct {
	Next State
}

// Process messages
func (state *AuthedStart) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	_, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	c.SendRawf("<?xml version='1.0'?><stream:stream id='%x' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>", createCookie())
	c.SendRaw("<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>")
	return state.Next, c, nil
}

// AuthedStream state
type AuthedStream struct {
	Next State
}

// Process messages
func (state *AuthedStream) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	se, err := c.Next()
	if err != nil {
		return nil, c, err
	}
	// check that it's a bind request
	// read bind request
	_, val, err := c.Read(se)
	if err != nil {
		return nil, c, err
	}
	switch v := val.(type) {
	case *ClientIQ:
		// TODO: actually validate that it's a bind request
		if v.Bind.Resource == "" {
			client.resourcepart = makeResource()
		} else {
			s.Log.Error(errors.New("Invalid bind request").Error())
			return nil, c, err
		}
		client.jid = client.localpart + "@" + client.domainpart + "/" + client.resourcepart
		c.SendRawf("<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>", v.ID, client.jid)

		s.ConnectBus <- Connect{Jid: client.jid, Receiver: client.messages}
	default:
		s.Log.Error(errors.New("Expected ClientIQ message").Error())
		return nil, c, err
	}
	return state.Next, c, nil
}

// Normal state
type Normal struct{}

// Process messages
func (state *Normal) Process(c *Connection, client *Client, s *Server) (State, *Connection, error) {
	var err error
	readDone := make(chan bool)
	errors := make(chan error)

	// one go routine to read/respond
	go func(done chan bool, errors chan error) {
		for {
			se, err := c.Next()
			if err != nil {
				errors <- err
				done <- true
				return
			}
			_, val, _ := c.Read(se)

			for _, extension := range s.Extensions {
				extension.Process(val, client)
			}
		}
	}(readDone, errors)

	for {
		select {
		case msg := <-client.messages:
			switch msg.(type) {
			default:
				err = c.SendStanza(msg)
			case string:
				err = c.SendRaw(msg.(string))
			}
			if err != nil {
				errors <- err
			}
		case <-readDone:
			return nil, c, nil
		case err := <-errors:
			s.Log.Error(fmt.Sprintf("Connection Error: %s", err.Error()))
		}
	}
}
