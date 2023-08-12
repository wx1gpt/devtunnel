package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/x/config"
	"github.com/mikkeloscar/sshconfig"
	"github.com/sgreben/sshtunnel"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var (
	composeFile = flag.String("compose-file", "docker-compose.yml", "Path to docker-compose.yml file")
	sshuser     = flag.String("ssh-user", "root", "SSH user")
	sshpass     = flag.String("ssh-pass", "", "SSH password")
	remote      = flag.String("remote", "", "Remote host ssh server of tunnel")
	target      = flag.String("target", "", "Target host ssh server of tunnel")
	mappings    = flag.String("mappings", "", "Port mappings")
	privateKey  = flag.String("private-key", "", "Private key file")
)

type Service struct {
	Name  string
	Ports []Ports
}

type Ports struct {
	TargetPort int
	ProxyPort  int
}

func main() {
	flag.Parse()

	if *remote == "" {
		log.Fatal("remote host is required")
	}

	// Load the docker-compose.yml file.
	services, err := loadServices(*composeFile)
	if err != nil {
		log.Fatalf("Failed to load docker-compose.yml file: %v", err)
	}

	log.Printf("Loaded %d services from %s", len(services), *composeFile)
	// mappings, err := buildMappings(services, *mappings)
	// if err != nil {
	// 	log.Fatalf("Failed to build mappings: %v", err)
	// }

	cfg, err := buildConfigFrom(services, *remote)
	if err != nil {
		log.Fatalf("Failed to build config: %v", err)
	}

	config.Set(cfg)

	for _, svc := range buildService(config.Global()) {
		svc := svc
		go func() {
			if err := svc.Serve(); err != nil {
				log.Fatalf("Failed to serve: %v", err)
			}
		}()
	}

	// tunnel, err := openTunnel(*privateKey, *remote, *target)
	// if err != nil {
	// 	log.Fatalf("Failed to open tunnel: %v", err)
	// }

	// var ctx = context.Background()

	// for _, srv := range services {
	// 	fmt.Printf("mapping service %s ports\n", srv.Name)
	// 	for _, ports := range srv.Ports {
	// 		targetPort := ports.TargetPort
	// 		if port, ok := mappings[srv.Name][ports.TargetPort]; ok {
	// 			targetPort = port
	// 		}

	// 		if err := tunnel.Proxy(ctx, targetPort, ports.TargetPort); err != nil {
	// 			log.Fatalf("Failed to proxy port %d: %v", ports.TargetPort, err)
	// 		}

	// 	}
	// }

	fmt.Println("success to tunnel all ports")
	var ch = make(chan os.Signal, 0)
	<-ch

	// keyPath := "private-key.pem"
	// authConfig := sshtunnel.ConfigAuth{
	// 	Keys: []sshtunnel.KeySource{{Path: &keyPath}},
	// }
	// sshAuthMethods, _ := authConfig.Methods()
	// clientConfig := ssh.ClientConfig{
	// 	User:            "ubuntu",
	// 	Auth:            sshAuthMethods,
	// 	HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	// }
	// tunnelConfig := sshtunnel.Config{
	// 	SSHAddr:   "my-ssh-server-host:22",
	// 	SSHClient: &clientConfig,
	// }

}

// getTunnelConfig returns a tunnel configuration based on the command line
// arguments.
func getTunnelConfig(privateKey string, remote string) (*sshtunnel.Config, error) {
	var (
		authConfig = sshtunnel.ConfigAuth{
			Keys: []sshtunnel.KeySource{{Path: &privateKey}},
		}
		sshAuthMethods, _ = authConfig.Methods()
		clientConfig      = ssh.ClientConfig{
			User:            *sshuser,
			Auth:            sshAuthMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		tunnelConfig = sshtunnel.Config{
			SSHAddr:   remote,
			SSHClient: &clientConfig,
		}
	)

	if privateKey == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		privateKey = filepath.Join(home, ".ssh/id_rsa")
		authConfig.Keys[0].Path = &privateKey
	}

	return &tunnelConfig, nil
}

// loadDockerComposeFile loads the docker-compose.yml file and returns the
// service configuration.
func loadServices(path string) ([]*Service, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var (
		composeService ComposeServices
		dec            = yaml.NewDecoder(f)
	)
	if err := dec.Decode(&composeService); err != nil {
		return nil, err
	}

	var services []*Service
	for name, srv := range composeService.Services.Services {
		var ports []Ports
		for _, port := range srv.Ports {
			sport := strings.Split(port, ":")
			if len(sport) != 2 {
				return nil, fmt.Errorf("invalid port mapping: %s", port)
			}

			ports = append(ports, Ports{
				TargetPort: toInt(sport[0]),
				ProxyPort:  toInt(sport[1]),
			})
		}

		services = append(services, &Service{
			Name:  name,
			Ports: ports,
		})
	}

	return services, nil
}

// buildMappings builds the port mappings from the command line arguments.
func buildMappings(services []*Service, mappings string) (map[string]map[int]int, error) {
	var mapping = make(map[string]map[int]int)
	for _, srv := range services {
		mapping[srv.Name] = make(map[int]int)
	}

	return mapping, nil
}

// openTunnel opens a tunnel to the remote host.
func openTunnel(privateKey, remote, target string) (*Tunnel, error) {
	// keyPath := "private-key.pem"
	tunnelConfig, err := getTunnelConfig(privateKey, remote)
	// tunnelCnfig, _, err := resolveSSHRemoteAddr(remote)
	if err != nil {
		return nil, err
	}

	return &Tunnel{
		config: tunnelConfig,
		target: target,
	}, nil
}

type Tunnel struct {
	config *sshtunnel.Config
	target string
}

// Proxy proxies the given port to the target port.
func (t *Tunnel) Proxy(ctx context.Context, port, targetPort int) error {
	var targetAddr string
	if t.target == "" {
		targetAddr = fmt.Sprintf("localhost:%d", targetPort)
	} else {
		targetAddr = fmt.Sprintf("%s:%d", t.target, targetPort)
	}

	// var laddr net.Addr
	// // fmt.Sprintf(":%d", )
	// laddr = &net.TCPAddr{
	// 	IP:   net.IPv4(127, 0, 0, 1),
	// 	Port: port,
	// }

	// var backoff = backoff.Config{
	// 	Min:         5 * time.Second,
	// 	Max:         30 * time.Second,
	// 	MaxAttempts: 10,
	// }

	// _, _, err := sshtunnel.ListenContext(ctx, laddr, "tcp", targetAddr, t.config, backoff)
	// return err

	conn, _, err := sshtunnel.DialContext(ctx, "tcp", targetAddr, t.config)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	for {
		localConn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go t.bindLocalConn(ctx, localConn, conn)
	}

	return nil
}

// bindLocalConn binds the given local connection to the remote connection.
func (t *Tunnel) bindLocalConn(ctx context.Context, localConn, remoteConn net.Conn) {
	// set remoteConn keepalive
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	}

	// set localConn keepalive
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	}

	go io.Copy(localConn, remoteConn)
	go io.Copy(remoteConn, localConn)
}

type ServiceMap map[string]dockerService

type dockerService struct {
	Ports []string
}

type ComposeServices struct {
	Version  string
	Services struct {
		Services ServiceMap `yaml:",inline"`
	}
}

// toInt converts the given string to an integer.
func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// resolveRemote resolves the ssh remote address from the given host.
// example:
//   - user@host:port
func resolveSSHRemoteAddr(addr string) (*sshtunnel.Config, bool, error) {
	var (
		sshAddr    string
		user       string
		port       int
		remoteAddr string
	)

	if isSSHRemoteAddr(addr) {
		// split user@host:port
		parts := strings.Split(addr, "@")
		if len(parts) == 2 {
			user = parts[0]
			addr = parts[1]
		}

		// split host:port
		parts = strings.Split(addr, ":")
		if len(parts) == 2 {
			sshAddr = parts[0]
			port = toInt(parts[1])
		} else {
			sshAddr = addr
			port = 22
		}

		// resolve host
		ips, err := net.LookupIP(sshAddr)
		if err != nil {
			return nil, false, err
		}

		// build remote address
		remoteAddr = fmt.Sprintf("%s:%d", ips[0].String(), port)
	} else if isIp(addr) {
		remoteAddr = addr
	} else {
		host, port, username, privatekey, err := resolveSSHConfig(addr)
		if err != nil {
			return nil, false, err
		}
		remoteAddr = fmt.Sprintf("%s:%d", host, port)
		user = username
		privateKey = &privatekey
	}
	// build ssh config
	var (
		authConfig = sshtunnel.ConfigAuth{
			Keys: []sshtunnel.KeySource{{Path: privateKey}},
		}
		sshAuthMethods, _ = authConfig.Methods()
		clientConfig      = ssh.ClientConfig{
			User:            user,
			Auth:            sshAuthMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		tunnelConfig = sshtunnel.Config{
			SSHAddr:   remoteAddr,
			SSHClient: &clientConfig,
		}
	)

	return &tunnelConfig, true, nil
}

// isSSHRemoteAddr returns true if the given address is a ssh remote address.
func isSSHRemoteAddr(addr string) bool {
	return strings.Contains(addr, "@")
}

// isIp returns true if the given address is an ip address.
func isIp(addr string) bool {
	return net.ParseIP(addr) != nil
}

// resolveSSHConfig resolves the ssh config from the given host.
func resolveSSHConfig(name string) (host string, port int, user string, privatekey string, err error) {
	// load home path ~/.ssh/config
	var home string
	home, err = os.UserHomeDir()
	if err != nil {
		return "", 0, "", "", err
	}

	sshConfigPath := filepath.Join(home, ".ssh", "config")

	hosts, err := sshconfig.Parse(sshConfigPath)
	for _, host := range hosts {
		for _, alias := range host.Host {
			if alias == name {
				return host.HostName, host.Port, host.User, host.IdentityFile, nil
			}
		}
	}

	return
}
