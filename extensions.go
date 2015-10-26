package xmpp

import "fmt"

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
	e.Log.Debug(fmt.Sprintf("Processing message: %s", message))
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

// PresenceExtension handles ClientIQ presence requests and updates
type PresenceExtension struct {
	MessageBus chan<- Message
	Accounts   AccountManager
}

// Process responds to Presence requests from a client
func (e *PresenceExtension) Process(message interface{}, from *Client) {
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
