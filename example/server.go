package main

import (
  "flag"
  "io"
  "io/ioutil"
  "log"
  "os"
  "strconv"
  "net"
  "crypto/tls"
  "github.com/tam7t/xmpp"
  "sync"
)

var (
  Info    *log.Logger
  Debug   *log.Logger
  Error   *log.Logger
)

func initLogger(debug bool) {
  var debugHandle, infoHandle, errorHandle io.Writer

  if debug {
    debugHandle = os.Stdout
  } else {
    debugHandle = ioutil.Discard
  }

  infoHandle = os.Stdout
  errorHandle = os.Stdout

  Info = log.New(infoHandle,
                 "INFO: ",
                log.Ldate|log.Ltime|log.Lshortfile)

  Debug = log.New(debugHandle,
                 "DEBUG: ",
                log.Ldate|log.Ltime|log.Lshortfile)

  Error = log.New(errorHandle,
                 "ERROR: ",
                log.Ldate|log.Ltime|log.Lshortfile)
}

func portString(portPtr *int) string {
  return ":" + strconv.Itoa(*portPtr)
}


var Registered map[string]string

var Users map[string]chan<- interface{}

var db_lock sync.Mutex

func authCallback(username, password string) (success bool, err error) {
  db_lock.Lock()
  defer db_lock.Unlock()

  Info.Println("auth callback")

    if Registered[username] == password {
      Info.Println("auth success")
      success = true
    } else {
      Info.Println("auth fail")
      success = false
    }

  return
}

func createCallback(username, password string) (success bool, err error) {
  db_lock.Lock()
  defer db_lock.Unlock()
  Info.Println("create callback")


  if _, ok := Registered[username]; ok {
    success = false
  } else {
    Registered[username] = password
  }
  return
}

func registerMessagesCallback(jid string, messagesToSendClient chan<- interface{}) {
  db_lock.Lock()
  defer db_lock.Unlock()

  Users[jid] = messagesToSendClient
}

func activeRosterCallback(jid string) (online []string) {
  db_lock.Lock()
  defer db_lock.Unlock()

  for person := range Users {
    online = append(online, person)
  }
  return
}

func main() {

  Registered = make( map[string]string )
  Registered["tmurphy"] = "password"

  Users = make ( map[string]chan<- interface{} )


  portPtr := flag.Int("port", 8080, "port number to listen on")
  debugPtr := flag.Bool("debug", false, "turn on debug logging")
  flag.Parse()

  initLogger(*debugPtr)

  Info.Println("starting server")
  Info.Println("listening on localhost:" + strconv.Itoa(*portPtr))

  // Listen for incoming connections.
  listener, err := net.Listen("tcp", portString(portPtr))
  if err != nil {
      Error.Println("could not listen for connections: ", err.Error())
      os.Exit(1)
  }
  defer listener.Close()

  var cert, _ = tls.LoadX509KeyPair("./cert.pem", "./key.pem")
  var tlsConfig = tls.Config{
      MinVersion: tls.VersionTLS10,
      Certificates: []tls.Certificate{cert},
      CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
  }

  xmppConfig := &xmpp.Config{
      Log:                          os.Stdout,
      Domain:                       "example.com",
      AuthenticateAccountCallback:  authCallback,
      CreateAccountCallback:        createCallback,
      RegisterInboundMessages:      registerMessagesCallback,
      UserRosterCallback:           activeRosterCallback,
      TLSConfig:                    &tlsConfig,
  }

  var messageBus = make(chan xmpp.RoutableMessage)

  go message_router(messageBus)

  for {
      // Listen for an incoming connection.
      conn, err := listener.Accept()

      if err != nil {
          Error.Println("could not accept connection: ", err.Error())
          os.Exit(1)
      }

      go xmpp.TcpAnswer(conn, messageBus, xmppConfig)
  }
}

func message_router(messageBus <-chan xmpp.RoutableMessage) {
  var channel chan<- interface{}
  var ok bool

  for {
    message := <- messageBus
    db_lock.Lock()

    if channel, ok = Users[message.To]; ok {
      channel <- message.Data
    }

    db_lock.Unlock()
  }
}