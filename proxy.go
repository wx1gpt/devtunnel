package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/service"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/config/parsing"
	xlogger "github.com/go-gost/x/logger"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
)

func buildConfigFrom(services []*Service, remote string) (*config.Config, error) {
	var (
		cfg   = &config.Config{}
		chain *config.ChainConfig
	)

	if len(remote) > 0 {
		chain = &config.ChainConfig{
			Name: fmt.Sprintf("chain-0"),
		}

		cfg.Chains = append(cfg.Chains, chain)
	} else {
		return nil, errors.New("remote address is required")
	}

	nodeConfig := buildNodeConfig(remote)
	nodeConfig.Name = fmt.Sprintf("node-0")

	var nodes []*config.NodeConfig
	for _, host := range strings.Split(nodeConfig.Addr, ",") {
		if host == "" {
			continue
		}
		nodeCfg := &config.NodeConfig{}
		*nodeCfg = *nodeConfig
		nodeCfg.Name = fmt.Sprintf("node-%d", len(nodes))
		nodeCfg.Addr = host
		nodes = append(nodes, nodeCfg)
	}

	mc := nodeConfig.Connector.Metadata
	// md := mdx.NewMetadata(mc)

	hopConfig := &config.HopConfig{
		Name:     fmt.Sprintf("hop-%d", 0),
		Selector: parseSelector(mc),
		Nodes:    nodes,
	}
	chain.Hops = append(chain.Hops, hopConfig)

	for _, svc := range services {
		svcs, err := buildServiceConfig(svc)
		if err != nil {
			return nil, err
		}

		// service.Name = fmt.Sprintf("%sservice-%d", i)
		cfg.Services = append(cfg.Services, svcs...)

		for _, svc := range svcs {
			svc.Handler.Chain = chain.Name
		}
	}

	parsing.BuildDefaultTLSConfig(cfg.TLS)

	return cfg, nil
}

func buildNodeConfig(remote string) *config.NodeConfig {
	var connector, dialer string = "sshd", "sshd"

	var node = &config.NodeConfig{
		Addr: remote,
	}

	if c := registry.ConnectorRegistry().Get("sshd"); c == nil {
		connector = "sshd"
	}

	if d := registry.DialerRegistry().Get(dialer); d == nil {
		dialer = "sshd"
	}

	var auth *config.AuthConfig
	if sshuser != nil {
		auth = &config.AuthConfig{
			Username: *sshuser,
		}
		if sshpass != nil {
			auth.Password = *sshpass
		}
	}

	var m = make(map[string]any)

	if privateKey != nil {
		m["privateKeyFile"] = *privateKey
	}

	node.Connector = &config.ConnectorConfig{
		Type:     connector,
		Auth:     auth,
		Metadata: m,
	}
	node.Dialer = &config.DialerConfig{
		Type:     dialer,
		TLS:      nil,
		Metadata: m,
	}

	if node.Dialer.Type == "ssh" || node.Dialer.Type == "sshd" {
		node.Connector.Auth = nil
		node.Dialer.Auth = auth
	}

	return node
}

func buildServiceConfig(service *Service) (svcs []*config.ServiceConfig, err error) {
	var (
		handler  = "tcp"
		listener = "tcp"
	)

	for _, ports := range service.Ports {
		var addr = fmt.Sprintf(":%d", ports.TargetPort)
		svc := &config.ServiceConfig{
			Addr: addr,
			Name: fmt.Sprintf("service-%d", ports.TargetPort),
		}

		if h := registry.HandlerRegistry().Get(handler); h == nil {
			handler = "tcp"
		}
		if ln := registry.ListenerRegistry().Get(listener); ln == nil {
			listener = "tcp"
			if handler == "ssu" {
				listener = "udp"
			}
		}

		if target != nil {
			target := *target
			if target == "" {
				target = "127.0.0.1"
			}

			addr := fmt.Sprintf("%s:%d", target, ports.TargetPort)
			svc.Forwarder = &config.ForwarderConfig{
				// Targets: strings.Split(remotes, ","),
			}
			svc.Forwarder.Nodes = append(svc.Forwarder.Nodes,
				&config.ForwardNodeConfig{
					Name: fmt.Sprintf("target-%d", 0),
					Addr: addr,
				})
		}

		m := make(map[string]any)
		if svc.Forwarder != nil {
			svc.Forwarder.Selector = parseSelector(m)
		}
		svc.Handler = &config.HandlerConfig{
			Type:     handler,
			Metadata: m,
		}
		svc.Listener = &config.ListenerConfig{
			Type:     listener,
			Metadata: m,
		}

		svcs = append(svcs, svc)
	}

	return svcs, nil
}

func buildService(cfg *config.Config) (services []service.Service) {
	for _, hostsCfg := range cfg.Hosts {
		if h := parsing.ParseHosts(hostsCfg); h != nil {
			if err := registry.HostsRegistry().Register(hostsCfg.Name, h); err != nil {
				log.Fatal(err)
			}
		}
	}

	for _, hopCfg := range cfg.Hops {
		hop, err := parsing.ParseHop(hopCfg)
		if err != nil {
			log.Fatal(err)
		}
		if hop != nil {
			if err := registry.HopRegistry().Register(hopCfg.Name, hop); err != nil {
				log.Fatal(err)
			}
		}
	}

	for _, chainCfg := range cfg.Chains {
		c, err := parsing.ParseChain(chainCfg)
		if err != nil {
			log.Fatal(err)
		}
		if c != nil {
			if err := registry.ChainRegistry().Register(chainCfg.Name, c); err != nil {
				log.Fatal(err)
			}
		}
	}

	for _, svcCfg := range cfg.Services {
		svc, err := parsing.ParseService(svcCfg)
		if err != nil {
			log.Fatal(err)
		}
		if svc != nil {
			if err := registry.ServiceRegistry().Register(svcCfg.Name, svc); err != nil {
				log.Fatal(err)
			}
		}
		services = append(services, svc)
	}

	return services
}

func parseSelector(m map[string]any) *config.SelectorConfig {
	md := mdx.NewMetadata(m)
	strategy := mdutil.GetString(md, "strategy")
	maxFails := mdutil.GetInt(md, "maxFails", "max_fails")
	failTimeout := mdutil.GetDuration(md, "failTimeout", "fail_timeout")
	if strategy == "" && maxFails <= 0 && failTimeout <= 0 {
		return nil
	}
	if strategy == "" {
		strategy = "round"
	}
	if maxFails <= 0 {
		maxFails = 1
	}
	if failTimeout <= 0 {
		failTimeout = 30 * time.Second
	}

	delete(m, "strategy")
	delete(m, "maxFails")
	delete(m, "max_fails")
	delete(m, "failTimeout")
	delete(m, "fail_timeout")

	return &config.SelectorConfig{
		Strategy:    strategy,
		MaxFails:    maxFails,
		FailTimeout: failTimeout,
	}
}

func init() {
	logger.SetDefault(xlogger.NewLogger())
}
