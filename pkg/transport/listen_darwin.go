package transport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
)

const DefaultURL = "vsock://vm_directory:1024"

func Listen(endpoint string) (net.Listener, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "vsock":
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return nil, err
		}
		path := path.Join(parsed.Hostname(), fmt.Sprintf("00000002.%08x", port))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		return net.ListenUnix("unix", &net.UnixAddr{
			Name: path,
			Net:  "unix",
		})
	case "unix":
		return net.Listen("unix", parsed.Path)
	default:
		return nil, errors.New("unexpected scheme")
	}
}
