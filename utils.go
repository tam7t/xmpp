package xmpp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

// RemoveResourceFromJid returns the user@domain portion of a JID.
func RemoveResourceFromJid(jid string) string {
	slash := strings.Index(jid, "/")
	if slash != -1 {
		return jid[:slash]
	}
	return jid
}

// domainFromJid returns the domain of a full or bare JID.
func domainFromJid(jid string) string {
	jid = RemoveResourceFromJid(jid)
	at := strings.Index(jid, "@")
	if at != -1 {
		return jid[at+1:]
	}
	return jid
}

// Cookie is used to give a unique identifier to each request.
type Cookie uint64

func createCookie() Cookie {
	var buf [8]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return Cookie(binary.LittleEndian.Uint64(buf[:]))
}

func makeResource() string {
	var buf [16]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return fmt.Sprintf("%x", buf)
}
