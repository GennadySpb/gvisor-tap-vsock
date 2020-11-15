package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/hashicorp/yamux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ip       string
	port     int
	endpoint string
)

func main() {
	flag.StringVar(&ip, "ip", "192.168.127.1", "ip of the host")
	flag.IntVar(&port, "port", 9090, "port of the host")
	flag.StringVar(&endpoint, "url", "/tmp/network.sock", "url of the daemon")
	flag.Parse()

	if err := run(); err != nil {
		logrus.Fatal(err)
	}
}

func run() error {
	conn, err := net.Dial("unix", endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
	defer conn.Close()

	req, err := http.NewRequest("POST", fmt.Sprintf("/listen-tunnel?ip=%s&port=%d", ip, port), nil)
	if err != nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`Hello world!\n`))
	})
	return http.Serve(session, mux)
}
