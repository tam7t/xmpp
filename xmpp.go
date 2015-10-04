// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"crypto/tls"
	"net"
)

// Client represents an xmpp connection
type Client struct {
	jid          string
	localpart    string
	domainpart   string
	resourcepart string
	messages     chan interface{}
}

// Messages returns a read-only channel of the messages that need to be
// sent to the client
func (c *Client) Messages() chan<- interface{} {
	return c.messages
}

// SendMessage allows anyone to send a message to the client
func (c *Client) SendMessage(message interface{}) {
	c.messages <- message
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

	// Extensions are injectable handlers that process messages
	Extensions []Extension

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

// Message is a generic XMPP message to send to the To Jid
type Message struct {
	To   string
	Data interface{}
}

// Connect holds a channel where the server can send messages to the specific Jid
type Connect struct {
	Jid      string
	Receiver chan<- interface{}
}

// Disconnect notifies when a jid disconnects
type Disconnect struct {
	Jid string
}

func (s *Server) TcpAnswer(conn net.Conn) (err error) {
	var c = new(Conn)
	s.Log.Info("Accepting TCP connection")

	c.in, c.out = makeInOut(conn)
	c.client.domainpart = s.Domain
}
