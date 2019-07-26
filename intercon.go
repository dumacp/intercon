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

func forward(client *ssh.Client, localAccept net.Conn, remoteAddr string, errch chan error) {
	defer close(errch)

	defer localAccept.Close()

	remote, err := client.Dial("tcp", remoteAddr)
	if err != nil {
		errch <- fmt.Errorf("connect to remote Addr ERROR: %v", err)
		return
	}
	defer remote.Close()

	ch1 := make(chan error, 0)
	ch2 := make(chan error, 0)
	go func() {
		defer close(ch1)
		if _, err := io.Copy(localAccept, remote); err != nil {
			select {
			case ch1 <- fmt.Errorf("Error in io.copy: %v", err):
			default:
				log.Printf("Error in io.copy: %v", err)
			}
		} else {
			select {
			case ch1 <- fmt.Errorf("exit ioCopy local -> remote"):
			default:
				log.Printf("Error in io.copy: %v", err)
			}
		}
	}()
	go func() {
		defer close(ch2)
		if _, err := io.Copy(remote, localAccept); err != nil {
			select {
			case ch2 <- fmt.Errorf("Error in io.copy: %v", err):
			default:
				log.Printf("Error in io.copy: %v", err)
			}
		} else {
			select {
			case ch2 <- fmt.Errorf("exit ioCopy remote -> local"):
			default:
				log.Printf("Error in io.copy: %v", err)
			}
		}
	}()

	select {
	case v := <-ch1:
		log.Println("select 1 !!!")
		select {
		case errch <- v:
		default:
			log.Printf("select 1 :%v!!!", v)
		}
	case v := <-ch2:
		log.Println("select 2 !!!")
		select {
		case errch <- v:
		default:
			log.Printf("select 2 :%v!!!", v)
		}
	}
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

	listen, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("listen in local Addr ERROR: %v", err)
	}
	defer listen.Close()
	for {
		log.Println("Waiting .... Accept")
		localAccept, err := listen.Accept()
		if err != nil {
			log.Printf("listen in local Addr ERROR: %v", err)
			continue
		}
		go func() {
			errch := make(chan error, 0)
			go forward(client, localAccept, remoteAddr, errch)
			for err := range errch {
				log.Printf("forward ERROR: %v", err)
			}
			log.Println("Done!!!")
		}()
	}
}
