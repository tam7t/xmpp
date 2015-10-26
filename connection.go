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
	// commands to control concurrent access to Raw connection
	readStartOps   chan readStartOp
	readElementOps chan readElementOp
	writeOps       chan writeOp
}

type readStartResponse struct {
	element xml.StartElement
	err     error
}

// readStartOp is the command to find the next xml start element
type readStartOp struct {
	resp chan readStartResponse
}

type readElementResponse struct {
	name xml.Name
	data interface{}
	err  error
}

// readElementOp is the command to read the next xml StartElement
type readElementOp struct {
	se   xml.StartElement
	resp chan readElementResponse
}

// writeOp is the command to write xml to the connection
type writeOp struct {
	message string
	resp    chan error
}

// NewConn creates a Connection struct for a given client, statemachine, and
// message system.
func NewConn(raw net.Conn, state State, client Client, MessageTypes map[xml.Name]reflect.Type) *Connection {
	conn := &Connection{
		Raw:            raw,
		State:          state,
		Client:         client,
		in:             xml.NewDecoder(raw),
		out:            xml.NewEncoder(raw),
		MessageTypes:   MessageTypes,
		readStartOps:   make(chan readStartOp),
		readElementOps: make(chan readElementOp),
		writeOps:       make(chan writeOp),
	}
	go conn.start()
	return conn
}

// readStart scans the stream to find the next xml.StartElement
func (c *Connection) readStart() readStartResponse {
	// loop until a start element token is found
	for {
		nextToken, err := c.in.Token()
		if err != nil {
			return readStartResponse{xml.StartElement{}, err}
		}
		switch nextToken.(type) {
		case xml.StartElement:
			return readStartResponse{nextToken.(xml.StartElement), nil}
		}
	}
}

// readElement reads an element from the stream and reflects the interface of
// the any known message types
func (c *Connection) readElement(se xml.StartElement) readElementResponse {
	// Put start element in an interface and allocate one.
	var messageInterface interface{}
	var err error

	if messageType, present := c.MessageTypes[se.Name]; present {
		messageInterface = reflect.New(messageType).Interface()
	} else {
		return readElementResponse{
			xml.Name{},
			nil,
			errors.New("Unknown XMPP message " + se.Name.Space + " <" + se.Name.Local + "/>"),
		}
	}

	// Unmarshal into that storage.
	if err := c.in.DecodeElement(messageInterface, &se); err != nil {
		return readElementResponse{xml.Name{}, nil, err}
	}

	return readElementResponse{se.Name, messageInterface, nil}
}

// write sends the string across the connection
func (c *Connection) write(message string) error {
	_, err := c.Raw.Write([]byte(message))
	return err
}

// start goroutine processes messages in thread safe manner
func (c *Connection) start() {
	var err error

loop:
	for {
		select {
		case op, open := <-c.readStartOps:
			// process operation to find a start element
			if !open {
				break loop
			}
			op.resp <- c.readStart()
		case op, open := <-c.readElementOps:
			// process operation to read a start element
			if !open {
				break loop
			}
			op.resp <- c.readElement(op.se)
		case op, open := <-c.writeOps:
			// process operation to write a string
			if !open {
				break loop
			}
			op.resp <- c.write(op.message)
		}
	}

	// all channels are closing, should be safe to close the socket
	c.Raw.Close()
}

// Close shutsdown connections nicely
func (c *Connection) Close() {
	// close communiation channels
	close(c.readStartOps)
	close(c.readElementOps)
	close(c.writeOps)

	// flush channels
	for op := range c.readStartOps {
		close(op.resp)
	}
	for op := range c.readElementOps {
		close(op.resp)
	}
	for op := range c.writeOps {
		close(op.resp)
	}
}

// Next scans the stream to find the next xml.StartElement
func (c *Connection) Next() (xml.StartElement, error) {
	nextRequest := readStartOp{resp: make(chan readStartResponse)}
	c.readStartOps <- nextRequest
	nextResponse, closed := <-nextRequest.resp
	return nextResponse.element, nextResponse.err
}

// Read the Element from the stream and reflect interface to known message types
func (c *Connection) Read(se xml.StartElement) (xml.Name, interface{}, error) {
	readRequest := readElementOp{resp: make(chan readElementResponse)}
	c.readElementOps <- readRequest
	readResponse, closed := <-readRequest.resp
	return readResponse.name, readResponse.data, readResponse.err
}

// SendStanza XML encodes the interface and sends it across the connection
func (c *Connection) SendStanza(s interface{}) error {
	data, err := xml.Marshal(s)
	if err != nil {
		return err
	}
	message := string(data)
	writeRequest := writeOp{message: message, resp: make(chan error)}
	c.writeOps <- writeRequest
	err, closed := <-writeRequest.resp
	return err
}

// SendRaw sends the string across the connection
func (c *Connection) SendRaw(s string) error {
	writeRequest := writeOp{message: s, resp: make(chan error)}
	c.writeOps <- writeRequest
	err, closed := <-writeRequest.resp
	return err
}

// SendRawf formats and sends a string across the connection
func (c *Connection) SendRawf(format string, a ...interface{}) error {
	message := fmt.Sprintf(format, a...)
	writeRequest := writeOp{message: message, resp: make(chan error)}
	c.writeOps <- writeRequest
	err, closed := <-writeRequest.resp
	return err
}
