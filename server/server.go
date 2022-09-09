package sshd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host       string
	Port       string
	Shell      string
	KeyFile    string
	KeySeed    string
	AuthType   string
	IgnoreEnv  bool
	LogVerbose bool
}

//Server is a simple SSH Daemon
type Server struct {
	c  *Config
	sc *ssh.ServerConfig
}

var (
	DEFAULT_SHELL string = "sh"
)

//NewServer creates a new Server
func NewServer(c *Config) (*Server, error) {

	sc := &ssh.ServerConfig{}
	s := &Server{c: c, sc: sc}

	c.Shell = "bash"

	p, err := exec.LookPath(c.Shell)
	if err != nil {
		return nil, fmt.Errorf("Failed to find shell: %s", c.Shell)
	}
	c.Shell = p
	s.debugf("Session shell %s", c.Shell)

	var key []byte
	if c.KeyFile != "" {
		//user provided key (can generate with 'ssh-keygen -t rsa')
		b, err := ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to load keyfile")
		}
		key = b
	}

	pri, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key")
	}

	sc.AddHostKey(pri)

	//setup auth
	//initial key parse
	keys, last, err := s.parseAuth(time.Time{})
	if err != nil {
		return nil, err
	}

	//setup checker
	sc.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		//update keys
		if ks, t, err := s.parseAuth(last); err == nil {
			keys = ks
			last = t
			s.debugf("Updated authorized keys")
		}
		k := string(key.Marshal())
		if cmt, exists := keys[k]; exists {
			s.debugf("User '%s' authenticated with public key", cmt)
			// return &ssh.Permissions{Extensions: map[string]string{"user_id": conn.User()}}, fmt.Errorf("Key accepted next steps")
			return nil, nil
		}
		s.debugf("User authentication failed with public key")
		return nil, fmt.Errorf("denied")
	}
	sc.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {

		slicename := []string{"TOTP:"}
		echo := []bool{true}
		client("TOTP", "Use the TOTP associated to your account", slicename, echo)

		return nil, nil
		// return &ssh.Permissions{Extensions: map[string]string{"user_id": conn.User()}}, nil
	}
	log.Printf("Authentication enabled (public keys #%d)", len(keys))

	return s, nil
}

func KeyboardInteractive(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	slicename := []string{"TOTP:"}
	echo := []bool{true}
	client("TOTP", "Use the TOTP associated to your account", slicename, echo)

	return nil, nil
	// return &ssh.Permissions{Extensions: map[string]string{"user_id": conn.User()}}, nil
}

//Start listening on port
func (s *Server) Start() error {
	h := s.c.Host
	p := s.c.Port
	var l net.Listener
	var err error

	//listen
	if p == "" {
		p = "22"
		l, err = net.Listen("tcp", h+":22")
		if err != nil {
			p = "2200"
			l, err = net.Listen("tcp", h+":2200")
			if err != nil {
				return fmt.Errorf("Failed to listen on 22 and 2200")
			}
		}
	} else {
		l, err = net.Listen("tcp", h+":"+p)
		if err != nil {
			return fmt.Errorf("Failed to listen on " + p)
		}
	}

	// Accept all connections
	log.Printf("Listening on %s:%s...", h, p)
	for {
		tcpConn, err := l.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sc)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to handshake (%s)", err)
			}
			continue
		}

		s.debugf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		// Print incoming out-of-band Requests
		go s.handleRequests(reqs)
		// Accept all channels
		go s.handleChannels(chans)
	}
}

func (s *Server) handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}

func (s *Server) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// allocate a terminal for this channel
		log.Print("creating pty...")
		// Create new pty
		f, tty, err := pty.Open()
		if err != nil {
			log.Printf("could not start pty (%s)", err)
			continue
		}

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = DEFAULT_SHELL
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])
					cmd := exec.Command(shell, []string{"-c", command}...)

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.Close()
						log.Printf("session closed")
					}()
				case "shell":
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"}
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("%s", err)
					}

					// Teardown session
					var once sync.Once
					close := func() {
						channel.Close()
						log.Printf("session closed")
					}

					// Pipe session to bash and visa-versa
					go func() {
						io.Copy(channel, f)
						once.Do(close)
					}()

					go func() {
						io.Copy(f, channel)
						once.Do(close)
					}()

					// We don't accept any commands (Payload),
					// only the default shell.
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true
					// Parse body...
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(f.Fd(), w, h)
					log.Printf("pty-req '%s'", termEnv)
				case "window-change":
					w, h := parseDims(req.Payload)
					SetWinsize(f.Fd(), w, h)
					continue //no response
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}

// =======================

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	log.Printf("window resize %dx%d", w, h)
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

func (s *Server) parseAuth(last time.Time) (map[string]string, time.Time, error) {

	info, err := os.Stat(s.c.AuthType)
	if err != nil {
		return nil, last, fmt.Errorf("Missing auth keys file")
	}

	t := info.ModTime()
	if t.Before(last) || t == last {
		return nil, last, fmt.Errorf("Not updated")
	}

	//grab file
	b, _ := ioutil.ReadFile(s.c.AuthType)
	lines := bytes.Split(b, []byte("\n"))
	//parse each line
	keys := map[string]string{}
	for _, l := range lines {
		if key, cmt, _, _, err := ssh.ParseAuthorizedKey(l); err == nil {
			keys[string(key.Marshal())] = cmt
		}
	}
	//ensure we got something
	if len(keys) == 0 {
		return nil, last, fmt.Errorf("No keys found in %s", s.c.AuthType)
	}
	return keys, t, nil
}

func (s *Server) debugf(f string, args ...interface{}) {
	if s.c.LogVerbose {
		log.Printf(f, args...)
	}
}

func appendEnv(env []string, kv string) []string {
	p := strings.SplitN(kv, "=", 2)
	k := p[0] + "="
	for i, e := range env {
		if strings.HasPrefix(e, k) {
			env[i] = kv
			return env
		}
	}
	return append(env, kv)
}
