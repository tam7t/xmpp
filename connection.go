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
	MessageTypes map[xml.Name]reflect.Type
	out          *xml.Encoder
	in           *xml.Decoder
}

// NewConn creates a Connection struct for a given net.Conn and message system
func NewConn(raw net.Conn, MessageTypes map[xml.Name]reflect.Type) *Connection {
	conn := &Connection{
		Raw:          raw,
		MessageTypes: MessageTypes,
		in:           xml.NewDecoder(raw),
		out:          xml.NewEncoder(raw),
	}
	return conn
}

// Next scans the stream to find the next xml.StartElement
func (c *Connection) Next() (xml.StartElement, error) {
	// loop until a start element token is found
	for {
		nextToken, err := c.in.Token()
		if err != nil {
			return xml.StartElement{}, err
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

	if messageType, present := c.MessageTypes[se.Name]; present {
		messageInterface = reflect.New(messageType).Interface()
	} else {
		return xml.Name{}, nil, errors.New("Unknown XMPP message " + se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err := c.in.DecodeElement(messageInterface, &se); err != nil {
		return xml.Name{}, nil, err
	}

	return se.Name, messageInterface, nil
}

// SendStanza XML encodes the interface and sends it across the connection
func (c *Connection) SendStanza(s interface{}) error {
	data, err := xml.Marshal(s)
	if err != nil {
		return err
	}
	_, err = c.Raw.Write(data)
	return err
}

// SendRaw sends the string across the connection
func (c *Connection) SendRaw(s string) error {
	_, err := c.Raw.Write([]byte(s))
	return err
}

// SendRawf formats and sends a string across the connection
func (c *Connection) SendRawf(format string, a ...interface{}) error {
	_, err := fmt.Fprintf(c.Raw, format, a...)
	return err
}
