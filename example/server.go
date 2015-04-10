package main

import (
	"github.com/tam7t/xmpp"

	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
)

/* Inject logging into xmpp library */

type Logger struct {
	info  bool
	debug bool
}

func (l Logger) Info(msg string) (err error) {
	if l.info {
		_, err = fmt.Printf("INFO: %s\n", msg)
	}
	return err
}

func (l Logger) Debug(msg string) (err error) {
	if l.debug {
		_, err = fmt.Printf("DEBUG: %s\n", msg)
	}
	return err
}

func (l Logger) Error(msg string) (err error) {
	_, err = fmt.Printf("ERROR: %s\n", msg)
	return err
}

/* Inject account management into xmpp library */

type AccountManager struct {
	Registered map[string]string
	lock       sync.Mutex
	log        Logger
}

func (a AccountManager) Authenticate(username, password string) (success bool, err error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.log.Info(fmt.Sprintf("authenticate: %s", username))

	if a.Registered[username] == password {
		a.log.Debug("auth success")
		success = true
	} else {
		a.log.Debug("auth fail")
		success = false
	}

	return
}

func (a AccountManager) CreateAccount(username, password string) (success bool, err error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.log.Info(fmt.Sprintf("create account: %s", username))

	if _, err := a.Registered[username]; err {
		success = false
	} else {
		a.Registered[username] = password
	}
	return
}

/* Inject message router into xmpp library */

type MessageRouter struct {
	Users map[string]chan<- interface{}
	lock  sync.Mutex
	log   Logger
	bus   chan xmpp.RoutableMessage
}

func (router MessageRouter) RegisterClient(jid string, publish chan<- interface{}) error {
	router.lock.Lock()
	defer router.lock.Unlock()

	router.log.Info(fmt.Sprintf("register client: %s", jid))

	router.Users[jid] = publish
	return nil
}

func (router MessageRouter) OnlineRoster(jid string) (online []string, err error) {
	router.lock.Lock()
	defer router.lock.Unlock()

	router.log.Info(fmt.Sprintf("retrieving roster: %s", jid))

	for person := range router.Users {
		online = append(online, person)
	}
	return
}

func (router MessageRouter) routeRoutine() {
	var channel chan<- interface{}
	var ok bool

	for {
		message := <-router.bus
		router.lock.Lock()

		if channel, ok = router.Users[message.To]; ok {
			channel <- message.Data
		}

		router.lock.Unlock()
	}
}

/* Main server loop */

func main() {
	portPtr := flag.Int("port", 8080, "port number to listen on")
	debugPtr := flag.Bool("debug", false, "turn on debug logging")
	flag.Parse()

	var registered = make(map[string]string)
	registered["tmurphy"] = "password"
	var active_users = make(map[string]chan<- interface{})
	var l = Logger{info: true, debug: *debugPtr}
	var am = AccountManager{Registered: registered, log: l}
	var mr = MessageRouter{Users: active_users, log: l, bus: make(chan xmpp.RoutableMessage)}

	var cert, _ = tls.LoadX509KeyPair("./cert.pem", "./key.pem")
	var tlsConfig = tls.Config{
		MinVersion:   tls.VersionTLS10,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
	}

	xmppConfig := &xmpp.Config{
		Log:       l,
		Router:    mr,
		Accounts:  am,
		Domain:    "example.com",
		TLSConfig: &tlsConfig,
	}

	l.Info("starting server")
	l.Info("listening on localhost:" + fmt.Sprintf("%d", *portPtr))

	// Listen for incoming connections.

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *portPtr))
	if err != nil {
		l.Error(fmt.Sprintf("could not listen for connections: ", err.Error()))
		os.Exit(1)
	}
	defer listener.Close()

	go mr.routeRoutine()

	for {
		conn, err := listener.Accept()

		if err != nil {
			l.Error(fmt.Sprintf("could not accept connection: ", err.Error()))
			os.Exit(1)
		}

		go xmpp.TcpAnswer(conn, mr.bus, xmppConfig)
	}
}
