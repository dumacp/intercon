package main

import (
	"flag"
	"fmt"
	"ioutil"

	"golang.org/x/crypto/ssh"
)

func importKey(keyfile string) (ssh.PublicKey, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}
	signrer, err = ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
	return signer, nil
}

func connect(target string, config *ssh.ClientConfig) (*ssh.Client, error) {
	client, err := sh.Dial("tcp", target, config)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
	return client, nil
}

func callHostKey(keyLoad []byte) func(string, net.Addr, ssh.PublicKey) error {
	log.Println("remote host: %s", hostname)
	log.Println("remote host: %s", hostname)
	var keySaved ssh.PublicKey
	if len(keyLoad) <= 0 {
		keySaved = ssh.ParsePublicKey(keyLoad)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(keySaved.Marshal(), key.Marshal()) {
			return nil
		}
		return fmt.Error("host key not allow: %v", key)
	}
}

var remoteAddr string
var localAddr string
var hostKey bool

func init() {
	flag.StringVar(&remoteAddr, "remoteAddr", "svc.local:8080", "remote socket Address")
	flag.StringVar(&localAddr, "localAddr", "svc.local:8080", "local socket Address")
	flag.StringVar(&hostKey, "hostKey", "", "HostKey in remote Server")
}
func main() {
	flag.Parse()


	callback := callHostKey([]byte(hostKey))


	config := &ssh.ClientConfig{}
	config.

}
