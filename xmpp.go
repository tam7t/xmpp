// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xmpp implements the XMPP IM protocol, as specified in RFC 6120 and
// 6121.
package xmpp

import (
	"crypto/tls"
	"fmt"
	"net"
)

// Client xmpp connection
type Client struct {
	jid          string
	localpart    string
	domainpart   string
	resourcepart string
	messages     chan interface{}
}

// AccountManager performs roster management and authentication
type AccountManager interface {
	Authenticate(username, password string) (success bool, err error)
	CreateAccount(username, password string) (success bool, err error)
	OnlineRoster(jid string) (online []string, err error)
}

// Logging interface for library messages
type Logging interface {
	Debug(string) error
	Info(string) error
	Error(string) error
}

// Server contains options for an XMPP connection.
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

// TCPAnswer sends connection through the TSLStateMachine
func (s *Server) TCPAnswer(conn net.Conn) {
	defer conn.Close()
	var err error

	s.Log.Info(fmt.Sprintf("Accepting TCP connection from: %s", conn.RemoteAddr()))

	state := NewTLSStateMachine(s.SkipTLS)
	client := &Client{messages: make(chan interface{})}
	defer close(client.messages)

	clientConnection := NewConn(conn, MessageTypes)

	for {
		state, clientConnection, err = state.Process(clientConnection, client, s)
		s.Log.Debug(fmt.Sprintf("[state] %s", state))

		if err != nil {
			s.Log.Error(fmt.Sprintf("[%s] State Error: %s", client.jid, err.Error()))
			return
		}
		if state == nil {
			s.Log.Info(fmt.Sprintf("Client Disconnected: %s", client.jid))
			s.DisconnectBus <- Disconnect{Jid: client.jid}
			return
		}
	}
}
