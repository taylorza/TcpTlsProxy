package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

var tunnelEP *string
var remoteEP *string
var bufferSize *int
var useTLS *bool
var skipVerification *bool

func main() {
	tunnelEP = flag.String("tunnelEP", "localhost:23", "Local listening port")
	remoteEP = flag.String("remoteEP", "", "Remote endpoint (ip:port)")
	bufferSize = flag.Int("buf", 4096, "Read/Write bufferSize")
	useTLS = flag.Bool("useTLS", false, "Use TLS for remote connection")
	skipVerification = flag.Bool("skipVerification", false, "Skip certificate verification. Only applicable if useTLS is specified")

	flag.Parse()

	if *remoteEP == "" {
		fmt.Fprintln(os.Stderr, "Remote end point not specified, use -remoteEP")
		flag.Usage()
		os.Exit(-1)
	}

	start()
}

func start() {
	log.Printf("Start TCP-TLS Proxy listening at : %s", *tunnelEP)
	if *useTLS == false {
		log.Println("WARNING: Using non-secure connection to remote end point, specify -useTLS to secure remote connection.")
	} else if *skipVerification {
		log.Println("WARNING: Not verifying server certificates risks man in the middle attacks.")
	}

	ln, err := net.Listen("tcp", *tunnelEP)
	if err != nil {
		panic("Listen failed: " + err.Error())
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleClient(conn)
		} else {
			log.Printf("Accept failed : %s", err.Error())
		}
	}
}

func handleClient(client net.Conn) {
	defer client.Close()

	var server net.Conn
	var err error

	if *useTLS {
		var tlscfg *tls.Config
		if *skipVerification {
			tlscfg = &tls.Config{InsecureSkipVerify: true}
		}
		server, err = tls.Dial("tcp", *remoteEP, tlscfg)
	} else {
		server, err = net.Dial("tcp", *remoteEP)
	}

	if err != nil {
		log.Printf("Remote connection failed : %s", err.Error())
		return
	}
	defer server.Close()

	log.Printf("Tunnel established from %s to %s", client.RemoteAddr().String(), *remoteEP)

	var wg sync.WaitGroup

	wg.Add(2)
	go clientToServer(client, server, &wg)
	go serverToClient(client, server, &wg)
	wg.Wait()
}

func clientToServer(client net.Conn, server net.Conn, wg *sync.WaitGroup) {
	defer func() {
		client.Close()
		server.Close()
		wg.Done()
	}()

	buf := make([]byte, *bufferSize)
	for {
		n, err := client.Read(buf)
		if err != nil {
			log.Printf("Read from client : %s", err.Error())
			return
		}

		_, err = server.Write(buf[:n])
		if err != nil {
			log.Printf("Write to remote server : %s", err.Error())
			return
		}
	}
}

func serverToClient(client net.Conn, server net.Conn, wg *sync.WaitGroup) {
	defer func() {
		client.Close()
		server.Close()
		wg.Done()
	}()

	buf := make([]byte, *bufferSize)
	for {
		n, err := server.Read(buf)
		if err != nil {
			log.Printf("Read from remote server : %s", err.Error())
			return
		}

		_, err = client.Write(buf[:n])
		if err != nil {
			log.Printf("Write to client : %s", err.Error())
			return
		}
	}
}
