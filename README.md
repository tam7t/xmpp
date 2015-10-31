# Golang XMPP Server Library

## Overview
This is a fork of [github.com/agl/xmpp](https://github.com/agl/xmpp) modified
for use by an XMPP server.

## Goal
A pluggable architecture for writing a golang xmpp server supporting the
following [specifications](http://xmpp.org/xmpp-protocols/xmpp-extensions/):
* [RFC 6120: XMPP CORE](http://xmpp.org/rfcs/rfc6120.html)
* [RFC 6121: XMPP IM](http://xmpp.org/rfcs/rfc6121.html)
* [RFC 7395: XMPP Subprotocol for WebSocket](http://tools.ietf.org/html/rfc7395)
* [XEP-0045: Multi-User Chat](http://xmpp.org/extensions/xep-0045.html)
* [XEP-0198: Stream Management](http://xmpp.org/extensions/xep-0198.html)
* [XEP-0280: Message Carbons](http://xmpp.org/extensions/xep-0280.html)
* [XEP-0313: Message Archive Management](http://xmpp.org/extensions/xep-0313.html)

## Usage

```bash
$ go build example/server.go
$ ./server -help
Usage of ./server:
  -debug
    	turn on debug logging
  -port int
    	port number to listen on (default 5222)
```

## Creating a self signed certificate

```bash
$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes
```
