package xmpp

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"reflect"
)

// Connection represents a connection to an XMPP server.
type Connection struct {
	Raw          net.Conn
	State        State
	Client       Client
	MessageTypes map[xml.Name]reflect.Type
	out          *xml.Encoder
	in           *xml.Decoder
}

// NewConn creates a Connection struct for a given client, statemachine, and
// message system.
func NewConn(raw net.Conn, state State, client Client, MessageTypes map[xml.Name]reflect.Type) *Connection {
	return &Connection{
		Raw:          raw,
		State:        state,
		Client:       client,
		in:           xml.NewDecoder(raw),
		out:          xml.NewEncoder(raw),
		MessageTypes: MessageTypes,
	}
}

// ProcessClientMessages waits for messages that need to be sent to the client
// and sends them
func (c *Connection) ProcessClientMessages() {
	var err error

	for {
		message, open := <-c.Client.messages
		if !open {
			break
		}

		str, ok := message.(string)
		if ok {
			err = c.SendRaw(str)
		} else {
			err = c.SendStanza(message)
		}
		// Pass errors up a context
		// if err != nil {
		// 	s.Log.Error(err.Error())
		// }
	}
}

// Next scans the stream to find the next xml.StartElement
func (c *Connection) Next() (xml.StartElement, error) {
	for {
		nextToken, err := c.in.Token()
		if err != nil {
			return nextToken.(xml.StartElement), err
		}
		switch nextToken.(type) {
		case xml.StartElement:
			return nextToken.(xml.StartElement), nil
		}
	}
}

// Read the Element from the stream and reflect interface to known message types
func (c *Connection) Read(se xml.StartElement) (xml.Name, interface{}, error) {
	// Put start element in an interface and allocate one.
	var messageInterface interface{}
	var err error

	if messageType, present := c.MessageTypes[se.Name]; present {
		messageInterface = reflect.New(messageType).Interface()
	} else {
		return xml.Name{}, nil, errors.New("Unknown XMPP message " + se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err := c.in.DecodeElement(messageInterface, &se); err != nil {
		return xml.Name{}, nil, err
	}
	return se.Name, messageInterface, err
}

// SendStanza XML encodes the interface and sends it across the connection
func (c *Connection) SendStanza(s interface{}) error {
	return c.out.Encode(s)
}

// SendRaw sends the string across the connection
func (c *Connection) SendRaw(s string) error {
	_, err := fmt.Fprintf(c.Raw, s)
	return err
}

// SendRawf formats and sends a string across the connection
func (c *Connection) SendRawf(format string, a ...interface{}) error {
	_, err := fmt.Fprintf(c.Raw, format, a...)
	return err
}
