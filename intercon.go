package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func importKey(keyfile string) (ssh.Signer, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
	return signer, nil
}

func connect(target string, config *ssh.ClientConfig) (*ssh.Client, error) {
	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		return nil, fmt.Errorf("connect Error: %v", err)
	}
	return client, nil
}

func callHostKey(keyLoad []byte) func(string, net.Addr, ssh.PublicKey) error {
	if len(keyLoad) > 0 {
		keySaved, err := ssh.ParsePublicKey(keyLoad)
		if err != nil {
			return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				return fmt.Errorf("Error import key: %v", key)
			}
		}
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Printf("remote host: %s", hostname)
			log.Printf("remote address: %s", remote)
			log.Printf("remote puyblic key: %s", key)
			if bytes.Equal(keySaved.Marshal(), key.Marshal()) {
				return nil
			}
			return fmt.Errorf("host key not allow: %v", key)
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		log.Printf("remote host: %s", hostname)
		log.Printf("remote address: %s", remote)
		log.Printf("remote puyblic key: %s", key)
		return nil
	}
}

func forward(localAddr, remoteAddr net.Conn) chan error {
	errch := make(chan error, 1)
	ch1 := make(chan error, 0)
	ch2 := make(chan error, 0)
	go func() {
		defer close(ch1)
		if _, err := io.Copy(localAddr, remoteAddr); err != nil {
			ch1 <- fmt.Errorf("Error in io.copy: %v", err)
		} else {
			ch1 <- nil
		}
		log.Println("exit ioCopy local -> remote")
	}()
	go func() {
		defer close(ch2)
		if _, err := io.Copy(remoteAddr, localAddr); err != nil {
			ch2 <- fmt.Errorf("Error in io.copy: %v", err)
		} else {
			ch2 <- nil
		}
		log.Println("exit ioCopy remote -> local")
	}()

	go func() {
		defer close(errch)
		for {
			select {
			case v := <-ch1:
				errch <- v
				continue
			case v := <-ch2:
				errch <- v
				continue
			}
			break
		}

	}()
	return errch
}

var remoteAddr string
var serverAddr string
var localAddr string
var remoteUser string
var hostKey string
var pubKey string
var password string

func init() {
	flag.StringVar(&serverAddr, "serverAddr", "ssh-server:22", "remote SSH server Address")
	flag.StringVar(&remoteAddr, "remoteAddr", "svc.local:8080", "remote socket Address")
	flag.StringVar(&remoteUser, "remoteUser", "user", "remote user")
	flag.StringVar(&localAddr, "localAddr", "svc.local:8080", "local socket Address")
	flag.StringVar(&hostKey, "hostKey", "", "HostKey in remote Server")
	flag.StringVar(&pubKey, "pubKey", "", "pubKey to authentication")
	flag.StringVar(&password, "password", "", "password to authentication")
}
func main() {
	flag.Parse()
	log.Printf("remoteAddr: %s; localAddr: %s; serverAddr: %s", remoteAddr, localAddr, serverAddr)

	config := &ssh.ClientConfig{}
	config.User = remoteUser
	config.Auth = make([]ssh.AuthMethod, 0)

	var pKey ssh.Signer = nil
	if len(pubKey) > 0 {
		var err error
		pKey, err = importKey(pubKey)
		if err != nil {
			log.Fatalf("import key ERROR: %v", err)
		}
		log.Println("IMPORT KEY")
		config.Auth = append(config.Auth, ssh.PublicKeys(pKey))
	}

	if len(password) > 0 {
		config.Auth = append(config.Auth, ssh.Password(password))
	}

	callback := callHostKey([]byte(hostKey))
	config.HostKeyCallback = callback

	client, err := connect(serverAddr, config)
	if err != nil {
		log.Fatalf("connect ERROR: %v", err)
	}
	defer client.Close()

	remote, err := client.Dial("tcp", remoteAddr)
	if err != nil {
		log.Fatalf("connect to remote Addr ERROR: %v", err)
	}
	defer remote.Close()

	listen, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("listen in local Addr ERROR: %v", err)
	}
	defer listen.Close()
	for {
		localAccept, err := listen.Accept()
		if err != nil {
			log.Fatalf("Accept ERROR: %v", err)
		}
		log.Printf("Accept connection from: %v", localAccept)
		errch := forward(localAccept, remote)
		for err := range errch {
			log.Fatalf("forward ERROR: %v", err)
		}
		log.Println("Done!!!")
		localAccept.Close()
	}
}
