package xmpp

import "encoding/xml"

// Extension interface for processing normal messages
type Extension interface {
	Process(message interface{}, from *Client)
}

// DebugExtension just dumps data
type DebugExtension struct {
	Log Logging
}

// Process a message (write to debug logger)
func (e *DebugExtension) Process(message interface{}, from *Client) {
	data, _ := xml.Marshal(message)
	e.Log.Debug("Processing message: " + string(data))
}

// NormalMessageExtension handles client messages
type NormalMessageExtension struct {
	MessageBus chan<- Message
}

// Process sends `ClientMessage`s from a client down the `MessageBus`
func (e *NormalMessageExtension) Process(message interface{}, from *Client) {
	parsed, ok := message.(*ClientMessage)
	if ok {
		e.MessageBus <- Message{To: parsed.To, Data: message}
	}
}

// RosterExtension handles ClientIQ presence requests and updates
type RosterExtension struct {
	Accounts AccountManager
}

// Process responds to Presence requests from a client
func (e *RosterExtension) Process(message interface{}, from *Client) {
	parsed, ok := message.(*ClientIQ)

	// handle things we need to handle
	if ok && string(parsed.Query) == "<query xmlns='jabber:iq:roster'/>" {
		// respond with roster
		roster, _ := e.Accounts.OnlineRoster(from.jid)
		msg := "<iq id='" + parsed.ID + "' to='" + parsed.From + "' type='result'><query xmlns='jabber:iq:roster' ver='ver7'>"
		for _, v := range roster {
			msg = msg + "<item jid='" + v + "'/>"
		}
		msg = msg + "</query></iq>"

		// respond to client
		from.messages <- msg
	}
}

// PresenceExtension handles ClientIQ presence requests and updates
type PresenceExtension struct {
	PresenceBus chan<- Message
}

// Process responds to Presence message from a client
func (e *PresenceExtension) Process(message interface{}, from *Client) {
	parsed, ok := message.(*ClientPresence)
	if ok {
		// this is how you reply to a message: from.messages <- message

		// types:
		// subscribe
		// subscribed
		// unsubscribed

		// 1) check request and remove Resource

		// 2) put request on the presence bus
		// 3) put roster push on message bus
		// or
		// auto reply with 'subscribed' if invite in other direction

		// compose the presence message (from) put on a channel that
		// the server will then push to the message chan for all other clients
		// difficult to - alert the 'to' field of the message

		// if i receive a presense message from the client, put it on the presence
		// bus for broadcasting to subscribers/peers
		// server should alter message
		e.PresenceBus <- Message{To: parsed.To, Data: message}
	}
}
