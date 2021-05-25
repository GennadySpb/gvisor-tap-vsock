package interfaces

import "errors"

func BindToInterface(fd int, ifname string) error {
	return errors.New("not implemented on Windows")
}
