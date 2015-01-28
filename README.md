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

## Usage

```bash
$ ./server -debug -port=8081
```

## Creating a self signed certificate

```bash
$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes
```