package main

import (
	"bufio"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/connection/direct"
)

// configGenerateOptions holds CLI flags for the config generate subcommand
type configGenerateOptions struct {
	configPath string
	serverId   string
	userUUID   string
	routeIDs   []string
	json       bool
}

// configKeygenOptions holds CLI flags for the config keygen subcommand
type configKeygenOptions struct {
	json bool
}

// configDirectOptions holds CLI flags for the direct relay config subcommand
type configDirectOptions struct {
	platformId string
	callId     string
	username   string
	gateway    string
	peers      int
	json       bool
}

// configBootstrapOptions holds CLI flags for the config bootstrap subcommand
type configBootstrapOptions struct {
	output string
}

// newConfigCommand creates the config cobra command
func newConfigCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "config",
		Short: "Config generation and management utilities",
	}

	root.AddCommand(newConfigGenerateCommand())
	root.AddCommand(newConfigKeygenCommand())
	root.AddCommand(newConfigDirectCommand())
	root.AddCommand(newConfigBootstrapCommand())
	return root
}

// newConfigGenerateCommand creates the generate config cobra command
func newConfigGenerateCommand() *cobra.Command {
	opts := &configGenerateOptions{}

	cmd := &cobra.Command{
		Use:   "generate <server-id> <user-uuid> <route-id1> [route-id2 ...]",
		Short: "Generates a client config from server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 3 {
				return errors.New("expected at least 3 positional arguments: <server-id> <user-uuid> <route-id1> [route-id2 ...]")
			}
			opts.serverId = args[0]
			opts.userUUID = args[1]
			opts.routeIDs = args[2:]
			return configMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "config.json", "server config JSON file path")
	cmd.Flags().BoolVarP(&opts.json, "json", "j", false, "output config in json format")
	return cmd
}

// newConfigKeygenCommand creates the config keygen cobra command
func newConfigKeygenCommand() *cobra.Command {
	opts := &configKeygenOptions{}

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate ML-KEM-768 keys for config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return keygenMain(opts)
		},
	}

	cmd.Flags().BoolVar(&opts.json, "json", false, "print keys as a JSON object")
	return cmd
}

// newConfigDirectCommand creates the direct relay config cobra command
func newConfigDirectCommand() *cobra.Command {
	opts := &configDirectOptions{}

	cmd := &cobra.Command{
		Use:   "direct <platform-id> <call-id> <username> <gateway-addr>",
		Short: "Generates a direct relay connection client config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 4 {
				return errors.New("expected exactly 4 positional arguments")
			}
			opts.platformId = args[0]
			opts.callId = args[1]
			opts.username = args[2]
			opts.gateway = args[3]
			return directConfigMain(opts)
		},
	}

	cmd.Flags().IntVarP(&opts.peers, "peers", "n", 1, "how many peer connections to use")
	cmd.Flags().BoolVarP(&opts.json, "json", "j", false, "output config in json format")
	return cmd
}

// newConfigBootstrapCommand creates the interactive bootstrap cobra command
func newConfigBootstrapCommand() *cobra.Command {
	opts := &configBootstrapOptions{}

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Interactively create a server or service config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return bootstrapMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.output, "output", "o", "config.json", "output path for the generated config")
	return cmd
}

// configMain runs the config generate command
func configMain(opts *configGenerateOptions) error {
	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config json file: %w", err)
	}

	serversCfg, err := config.ParseServersConfig(configData)
	if err != nil {
		return fmt.Errorf("failed to parse config json file: %w", err)
	}

	serverCfg, err := serversCfg.GetServerConfig(opts.serverId)
	if err != nil {
		return fmt.Errorf("failed to parse server config for %s: %w", opts.serverId, err)
	}

	if err = serverCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate server config for %s: %w", opts.serverId, err)
	}

	innerCfg := serverCfg.GetInner().(config.ServerConfig)

	provider, err := serversCfg.GetProvider(innerCfg.Provider)
	if err != nil {
		return fmt.Errorf("failed to get provider for %s: %w", innerCfg.Provider, err)
	}

	defer provider.Stop()

	err = provider.Update(serversCfg.Providers[innerCfg.Provider])
	if err != nil {
		return fmt.Errorf("failed to configure provider for %s: %w", innerCfg.Provider, err)
	}

	connHandler, err := connection.GetHandler(innerCfg.Type)
	if err != nil {
		return fmt.Errorf("failed to get handler: %w", err)
	}

	user, err := provider.GetUser(opts.userUUID)
	if err != nil {
		return fmt.Errorf("failed to resolve user: %w", err)
	}

	routes := make([]*providers.Route, 0, len(opts.routeIDs))
	for _, rid := range opts.routeIDs {
		route, err := provider.GetRoute(rid)
		if err != nil {
			return fmt.Errorf("failed to resolve route %q: %w", rid, err)
		}
		routes = append(routes, route)
	}

	clientCfg, err := connHandler.GetClientConfig(user, routes)
	if err != nil {
		return fmt.Errorf("failed to generate client config: %w", err)
	}

	if err := clientCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate client config: %w", err)
	}

	if opts.json {
		out, err := clientCfg.ToJSON(false, false)
		if err != nil {
			return err
		}
		fmt.Println(out)
	} else {
		fmt.Println(clientCfg.ToURL())
	}

	return nil
}

// serverMain runs the keygen command
func keygenMain(opts *configKeygenOptions) error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}

	priv := base64.StdEncoding.EncodeToString(dk.Bytes())
	pub := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	if opts.json {
		payload := map[string]string{
			"priv_key": priv,
			"pub_key":  pub,
		}
		out, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("priv_key=%s\n", priv)
	fmt.Printf("pub_key=%s\n", pub)
	return nil
}

// directConfigMain runs the direct relay config command
func directConfigMain(opts *configDirectOptions) error {
	clientCfg := direct.ClientConfig{
		ClientConfig: config.ClientConfig{
			UserUUID:   "INSECURE-DIRECT-RELAY",
			PlatformID: opts.platformId,
			CallID:     opts.callId,
			Type:       "direct",
			Routes: []config.ClientRoute{
				{RouteID: "direct", Socket: "udp", Transport: "none"},
			},
		},
		Gateway: opts.gateway,
		Peers:   opts.peers,
	}

	if err := clientCfg.Validate(); err != nil {
		return fmt.Errorf("failed to validate client config: %w", err)
	}

	if opts.json {
		out, err := clientCfg.ToJSON(false, false)
		if err != nil {
			return err
		}
		fmt.Println(out)
	} else {
		fmt.Println(clientCfg.ToURL())
	}

	return nil
}

func prompt(r *bufio.Reader, msg, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", msg, def)
	} else {
		fmt.Printf("%s: ", msg)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptRequired(r *bufio.Reader, msg string) string {
	for {
		v := prompt(r, msg, "")
		if v != "" {
			return v
		}
		fmt.Println("* this field is required, please enter a value")
	}
}

func promptChoice(r *bufio.Reader, msg string, choices []string, def string) string {
	joined := strings.Join(choices, "/")
	for {
		fmt.Printf("%s (%s) [%s]: ", msg, joined, def)
		line, _ := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		for _, c := range choices {
			if strings.EqualFold(line, c) {
				return strings.ToLower(c)
			}
		}
		fmt.Printf("* invalid choice, pick one of %s\n", joined)
	}
}

func promptInt(r *bufio.Reader, msg string, def int) int {
	for {
		raw := prompt(r, msg, strconv.Itoa(def))
		v, err := strconv.Atoi(raw)
		if err == nil && v > 0 {
			return v
		}
		fmt.Println("* please enter a positive integer")
	}
}

func promptIntAtLeast(r *bufio.Reader, msg string, def, min int) int {
	for {
		raw := prompt(r, msg, strconv.Itoa(def))
		v, err := strconv.Atoi(raw)
		if err == nil && v >= min {
			return v
		}
		fmt.Printf("* please enter an integer >= %d\n", min)
	}
}

func promptIP(r *bufio.Reader, msg string) string {
	for {
		v := promptRequired(r, msg)
		if net.ParseIP(v) != nil {
			return v
		}
		fmt.Println("* invalid IP address, try again")
	}
}

func promptPort(r *bufio.Reader, msg string, def int) int {
	for {
		v := promptInt(r, msg, def)
		if v >= 1 && v <= 65535 {
			return v
		}
		fmt.Println("* port must be between 1 and 65535")
	}
}

// bootstrapMain runs the bootstrap config command
func bootstrapMain(opts *configBootstrapOptions) error {
	r := bufio.NewReader(os.Stdin)
	kind := promptChoice(r, "Config type", []string{"server", "service"}, "server")

	if kind == "service" {
		return bootstrapServiceMain(opts)
	}

	return bootstrapServerMain(opts)
}

// bootstrapServerMain runs the interactive server config wizard
func bootstrapServerMain(opts *configBootstrapOptions) error {
	r := bufio.NewReader(os.Stdin)

	fmt.Println("=== PROVIDER CONFIGURATION ===")
	providerConfigs := make(map[string]map[string]any)
	var providerIDs []string

	fmt.Println()
	firstProviderID, firstProviderCfg, err := configureProvider(r, 1)
	if err != nil {
		return err
	}
	providerConfigs[firstProviderID] = firstProviderCfg
	providerIDs = append(providerIDs, firstProviderID)
	fmt.Printf("* Provider %q configured\n", firstProviderID)

	addProviderStr := promptChoice(r, "Add another provider?", []string{"yes", "no"}, "no")
	providerCount := 2
	for addProviderStr == "yes" {
		fmt.Println()
		providerID, providerCfg, err := configureProvider(r, providerCount)
		if err != nil {
			return err
		}
		providerConfigs[providerID] = providerCfg
		providerIDs = append(providerIDs, providerID)
		fmt.Printf("* Provider %q configured\n", providerID)

		addProviderStr = promptChoice(r, "Add another provider?", []string{"yes", "no"}, "no")
		providerCount++
	}

	fmt.Println()
	fmt.Println("=== SERVER CONFIGURATION ===")
	servers := make(map[string]map[string]any)
	var serverIDs []string

	fmt.Println()
	fmt.Printf("Available providers: %s\n", strings.Join(providerIDs, ", "))
	firstServerID, firstServerCfg, err := configureRelayServer(r, providerIDs, 1)
	if err != nil {
		return err
	}
	servers[firstServerID] = firstServerCfg
	serverIDs = append(serverIDs, firstServerID)
	fmt.Printf("* Server %q configured\n", firstServerID)

	addServerStr := promptChoice(r, "Add another server?", []string{"yes", "no"}, "no")
	serverCount := 2
	for addServerStr == "yes" {
		fmt.Println()
		fmt.Printf("Available providers: %s\n", strings.Join(providerIDs, ", "))
		serverID, serverCfg, err := configureRelayServer(r, providerIDs, serverCount)
		if err != nil {
			return err
		}
		servers[serverID] = serverCfg
		serverIDs = append(serverIDs, serverID)
		fmt.Printf("* Server %q configured\n", serverID)

		addServerStr = promptChoice(r, "Add another server?", []string{"yes", "no"}, "no")
		serverCount++
	}

	serversConfig := map[string]any{
		"servers":   servers,
		"providers": providerConfigs,
	}

	outJSON, err := json.MarshalIndent(serversConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}

	if err := os.WriteFile(opts.output, outJSON, 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Println()
	fmt.Printf("* Configuration written to %s\n", opts.output)

	return nil
}

// configureProvider prompts the user to configure a provider and returns its ID and config
func configureProvider(r *bufio.Reader, index int) (string, map[string]any, error) {
	fmt.Printf("--- Provider #%d ---\n", index)
	providerType := promptChoice(r, "Provider type", []string{"raw", "json"}, "raw")

	var providerCfg map[string]any
	var providerID string

	if providerType == "json" {
		providerID = prompt(r, "Provider ID", fmt.Sprintf("provider_%d", index))
		jsonPath := prompt(r, "Path to provider JSON file", "provider.json")
		providerCfg = map[string]any{
			"type": "json",
			"path": jsonPath,
		}
	} else {
		providerID = prompt(r, "Provider ID", fmt.Sprintf("provider_%d", index))

		fmt.Println()
		addRouteStr := promptChoice(r, "Add a route now?", []string{"yes", "no"}, "yes")

		var routes []providers.Route
		for addRouteStr == "yes" {
			fmt.Println()
			routeID := promptRequired(r, "Route ID")
			address := promptIP(r, "Destination IP address")
			port := promptPort(r, "Destination port", 51820)
			socket := promptChoice(r, "Socket type", []string{"udp", "tcp"}, "udp")

			transports := common.TransportsHolder.List()
			if len(transports) == 0 {
				transports = []string{"none"}
			}

			transport := "none"
			if socket == "tcp" {
				transport = promptChoice(r, "Transport", transports, transports[0])
			} else {
				transport = promptChoice(r, "Transport", transports, "none")
			}

			encryption := promptChoice(r, "Encryption mode", []string{"handshake", "full"}, "handshake")
			displayName := prompt(r, "Display name for generated client configs", routeID)

			routes = append(routes, providers.Route{
				ID:         routeID,
				Address:    address,
				Port:       port,
				Socket:     socket,
				Transport:  transport,
				Encryption: encryption,
				Name:       displayName,
			})

			fmt.Printf("* Route %q added\n\n", routeID)
			addRouteStr = promptChoice(r, "Add another route?", []string{"yes", "no"}, "no")
		}

		fmt.Println()
		addUserStr := promptChoice(r, "Add a user now?", []string{"yes", "no"}, "yes")

		var users []providers.User
		var routeIDs []string
		for _, r := range routes {
			routeIDs = append(routeIDs, r.ID)
		}

		for addUserStr == "yes" {
			fmt.Println()

			var userUUID string
			for {
				userUUID = prompt(r, "User UUID (leave empty to auto-generate)", "")
				if userUUID == "" {
					userUUID = uuid.New().String()
					fmt.Printf("* Auto-generated UUID: %s\n\n", userUUID)
				} else if _, err := uuid.Parse(userUUID); err != nil {
					fmt.Println("* Invalid UUID")
					continue
				}

				break
			}

			fmt.Printf("Available routes: %s\n", strings.Join(routeIDs, ", "))
			allowedRaw := prompt(r, "Allowed routes (comma-separated, empty = all)", "")

			var allowedRoutes []string
			if strings.TrimSpace(allowedRaw) == "" {
				allowedRoutes = append([]string(nil), routeIDs...)
			} else {
				for _, rid := range strings.Split(allowedRaw, ",") {
					if rid = strings.TrimSpace(rid); rid != "" {
						allowedRoutes = append(allowedRoutes, rid)
					}
				}
			}

			connections := common.ConnectionsHolder.List()
			connType := promptChoice(r, "Connection type", connections, "relay")

			peers := promptInt(r, "Peer connections per session", 1)
			forceTurnStr := promptChoice(r, "Force TURN in P2P mode?", []string{"yes", "no"}, "no")

			users = append(users, providers.User{
				UUID:          userUUID,
				AllowedRoutes: allowedRoutes,
				Type:          connType,
				Peers:         peers,
				ForceTurn:     forceTurnStr == "yes",
			})

			fmt.Printf("* User %s added\n\n", userUUID)
			addUserStr = promptChoice(r, "Add another user?", []string{"yes", "no"}, "no")
		}

		providerCfg = map[string]any{
			"type":   "raw",
			"routes": routes,
			"users":  users,
		}
	}

	return providerID, providerCfg, nil
}

// configureRelayServer prompts the user to configure a relay server and returns its ID and config
func configureRelayServer(r *bufio.Reader, providerIDs []string, index int) (string, map[string]any, error) {
	fmt.Printf("--- Relay Server #%d ---\n", index)
	serverID := prompt(r, "Server ID", fmt.Sprintf("server_%d", index))

	platforms := common.PlatformsHolder.List()
	fmt.Printf("Available platforms: %s\n", strings.Join(platforms, ", "))
	platformID := promptChoice(r, "Platform ID", platforms, platforms[0])
	callID := promptRequired(r, "Call ID")

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", nil, fmt.Errorf("keygen: %w", err)
	}
	privKey := base64.StdEncoding.EncodeToString(dk.Bytes())
	pubKey := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	fmt.Println()
	publicIP := promptIP(r, "Server public IP")
	listenPort := promptPort(r, "Server UDP listen port", 56000)
	listenAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(listenPort))

	protos := common.ProtocolsHolder.List()
	if len(protos) == 0 {
		protos = []string{"none"}
	}
	proto := promptChoice(r, "Protocol", protos, "none")
	cloak := prompt(r, "Cloak method (leave empty for none)", "")

	fmt.Println()
	providerID := promptChoice(r, "Provider to use", providerIDs, providerIDs[0])

	serverCfg := map[string]any{
		"type":        "relay",
		"provider":    providerID,
		"platform_id": platformID,
		"call_id":     callID,
		"pub_key":     pubKey,
		"priv_key":    privKey,
		"proto":       proto,
		"cloak":       cloak,
		"public_ip":   publicIP,
		"listen_addr": listenAddr,
	}

	return serverID, serverCfg, nil
}

// bootstrapServiceMain runs the interactive service config wizard
func bootstrapServiceMain(opts *configBootstrapOptions) error {
	r := bufio.NewReader(os.Stdin)

	listenMode := promptChoice(r, "Service listener", []string{"unix", "tcp", "both"}, "unix")

	serviceCfg := config.ServiceConfig{}

	if listenMode == "unix" || listenMode == "both" {
		serviceCfg.UnixSocket = prompt(r, "Unix socket path", "/tmp/turnable.sock")
	}

	if listenMode == "tcp" || listenMode == "both" {
		listenIP := prompt(r, "Service TCP listen IP", "127.0.0.1")
		listenPort := promptPort(r, "Service TCP port", 45678)
		serviceCfg.ListenAddr = net.JoinHostPort(listenIP, strconv.Itoa(listenPort))
	}

	serviceCfg.PersistDir = prompt(r, "Persist dir (empty = disabled)", "")

	enableAuth := promptChoice(r, "Enable authentication?", []string{"yes", "no"}, "yes") == "yes"
	if enableAuth {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return fmt.Errorf("keygen: %w", err)
		}

		serviceCfg.PrivKey = base64.StdEncoding.EncodeToString(dk.Bytes())
		serviceCfg.PubKey = base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

		fmt.Println("* Service server keypair:")
		fmt.Printf("* pub_key=%s\n", serviceCfg.PubKey)
		fmt.Printf("* priv_key=%s\n", serviceCfg.PrivKey)

		userCount := promptIntAtLeast(r, "How many service users to generate?", 0, 0)
		for i := 1; i <= userCount; i++ {
			userDK, err := mlkem.GenerateKey768()
			if err != nil {
				return fmt.Errorf("user keygen %d: %w", i, err)
			}

			userPriv := base64.StdEncoding.EncodeToString(userDK.Bytes())
			userPub := base64.StdEncoding.EncodeToString(userDK.EncapsulationKey().Bytes())

			serviceCfg.AllowedKeys = append(serviceCfg.AllowedKeys, userPub)

			fmt.Println()
			fmt.Printf("* User %d keypair:\n", i)
			fmt.Printf("  pub_key=%s\n", userPub)
			fmt.Printf("  priv_key=%s\n", userPriv)
		}
	}

	if err := serviceCfg.Validate(); err != nil {
		return fmt.Errorf("generated service config failed validation: %w", err)
	}

	outJSON, err := serviceCfg.ToJSON(true)
	if err != nil {
		return fmt.Errorf("serialize service config: %w", err)
	}

	outPath := opts.output
	if outPath == "config.json" {
		outPath = "service.json"
	}

	if err := os.WriteFile(outPath, []byte(outJSON), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Println()
	fmt.Printf("* Service config written to %s\n", outPath)

	return nil
}
