package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/google/shlex"
	"github.com/spf13/cobra"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/service"
	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// serviceServerOptions holds CLI flags for the service server subcommand
type serviceServerOptions struct {
	configPath string // service config path
	persistDir string // directory for persisted state
	verbose    bool   // enable debug logging
}

// serviceClientOptions holds CLI flags for the service client subcommand
type serviceClientOptions struct {
	unixSocket string // unix socket of a local service
	serverAddr string // address of a remote service
	privKey    string // client private key
	pubKey     string // client public key
	serverKey  string // pinned service public key
	command    string // command to run, interactive when empty
}

// newServiceCommand creates the service cobra command
func newServiceCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "service",
		Short: "Service mode server and client",
	}

	root.AddCommand(newServiceServerCommand())
	root.AddCommand(newServiceClientCommand())
	return root
}

// newServiceServerCommand creates the service server cobra command
func newServiceServerCommand() *cobra.Command {
	opts := &serviceServerOptions{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Starts the service server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return serviceServerMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "service.json", "service config JSON file path")
	cmd.Flags().StringVarP(&opts.persistDir, "persist", "p", "", "directory to persist instance configs for auto-restart on startup")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "V", false, "enable verbose debug logging")
	return cmd
}

// newServiceClientCommand creates the service client cobra command
func newServiceClientCommand() *cobra.Command {
	opts := &serviceClientOptions{}

	cmd := &cobra.Command{
		Use:   "client [command]",
		Short: "Starts the service REPL client",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.command = strings.Join(args, " ")
			return serviceClientMain(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.unixSocket, "unix", "u", "", "unix socket file path to connect to")
	cmd.Flags().StringVarP(&opts.serverAddr, "address", "a", "", "TCP address and port to connect to")
	cmd.Flags().StringVarP(&opts.pubKey, "pub-key", "p", "", "client public ML-KEM-768 key for auth")
	cmd.Flags().StringVarP(&opts.privKey, "priv-key", "k", "", "client private ML-KEM-768 key for auth")
	cmd.Flags().StringVarP(&opts.serverKey, "server-key", "s", "", "service public ML-KEM-768 key to pin, protects against impersonation")
	return cmd
}

// serviceServerMain runs the service server command
func serviceServerMain(opts *serviceServerOptions) error {
	if opts.verbose {
		common.SetLogLevel(int(slog.LevelDebug))
	}

	config.Options.Interactive = false

	configData, err := os.ReadFile(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to read cfg json file: %w", err)
	}

	cfg, err := config.NewServiceConfigFromJSON(string(configData))
	if err != nil {
		return fmt.Errorf("failed to parse cfg json file: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate service cfg: %w", err)
	}

	slog.Info("starting service server")
	server, err := service.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("invalid service cfg: %w", err)
	}

	if opts.persistDir != "" {
		persistDir := resolve(opts.persistDir)
		if cfg.PersistDir != "" && resolve(cfg.PersistDir) != persistDir {
			slog.Warn("--persist overrides persist_dir from the service config", "config", cfg.PersistDir, "flag", persistDir)
		}

		server.SetPersistDir(persistDir)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start service server: %w", err)
	}

	slog.Info("service server started")

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	<-sigCh
	slog.Warn("CTRL+C received, stopping gracefully...")
	go func() {
		<-sigCh
		slog.Error("CTRL+C received, forcibly exiting...")
		os.Exit(130)
	}()

	slog.Info("stopping service server")
	if err := server.Stop(); err != nil {
		return fmt.Errorf("failed to stop service server: %w", err)
	}

	return nil
}

// printLogRecord formats and prints a server log record to stdout
func printLogRecord(rec *pb.LogRecord) {
	t := time.Unix(0, rec.Time)

	attrs := make([]any, len(rec.Attrs))
	for i, a := range rec.Attrs {
		attrs[i] = slog.String(a.Key, a.Value)
	}

	r := slog.NewRecord(t, slog.Level(rec.Level), rec.Message, 0)
	r.Add(attrs...)

	_ = slog.Default().Handler().Handle(context.Background(), r)
}

// resolve resolves a relative path to an absolute path
func resolve(relPath string) string {
	absPath, err := filepath.Abs(relPath)
	if err != nil {
		return relPath
	}

	return absPath
}

// splitAddrs splits comma separated addresses string into a string slice
func splitAddrs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseAutostart parses the optional autostart argument of a start command
func parseAutostart(parts []string) (bool, error) {
	if len(parts) < 6 {
		return false, nil
	}
	return strconv.ParseBool(parts[5])
}

// loadConfig loads config from file if path starts with @
func loadConfig(input string) (string, error) {
	if strings.HasPrefix(input, "@") {
		filePath := resolve(strings.TrimPrefix(input, "@"))
		content, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read config file %s: %w", filePath, err)
		}

		return strings.TrimSpace(string(content)), nil
	}

	return input, nil
}

// serviceClientMain runs the service CLI REPL
func serviceClientMain(opts *serviceClientOptions) error {
	if opts.serverAddr != "" && opts.unixSocket != "" {
		return errors.New("only one of --address or --unix can be set")
	}

	var clientMu sync.Mutex
	var client *service.Client
	var cachedInstances []*pb.InstanceInfo
	var cachedProviders []*pb.ProviderInfo
	logsEnabled := true

	getClient := func() *service.Client {
		clientMu.Lock()
		defer clientMu.Unlock()
		return client
	}

	refreshIDs := func() {
		c := getClient()
		if c == nil {
			return
		}
		if instances, err := c.ListInstances(); err == nil {
			cachedInstances = instances
		}

		if providers, err := c.ListProviders(); err == nil {
			cachedProviders = providers
		}
	}

	startWatcher := func(activeClient *service.Client) {
		go func() {
			for event := range activeClient.WatchEvents() {
				switch event.Kind {
				case service.EventLog:
					if logsEnabled {
						printLogRecord(event.Log)
					}
				case service.EventInstanceStarted:
					ev := event.InstanceEvent
					itype := "server"
					if ev.InstanceType == pb.InstanceType_INSTANCE_TYPE_CLIENT {
						itype = "client"
					}

					fmt.Printf("\n[instance started: id=%s name=%s type=%s]\n", ev.InstanceId, ev.Name, itype)
				case service.EventInstanceStopped:
					ev := event.InstanceEvent
					itype := "server"
					if ev.InstanceType == pb.InstanceType_INSTANCE_TYPE_CLIENT {
						itype = "client"
					}

					fmt.Printf("\n[instance stopped: id=%s name=%s type=%s]\n", ev.InstanceId, ev.Name, itype)
				case service.EventInstanceUpdated:
					ev := event.InstanceEvent
					fmt.Printf("\n[instance updated: id=%s name=%s]\n", ev.InstanceId, ev.Name)
				case service.EventInstanceCreated:
					ev := event.InstanceEvent
					fmt.Printf("\n[instance created: id=%s name=%s]\n", ev.InstanceId, ev.Name)
				case service.EventInstanceFailed:
					ev := event.InstanceEvent
					fmt.Printf("\n[instance failed: id=%s name=%s]\n", ev.InstanceId, ev.Name)
				case service.EventDisconnected:
					clientMu.Lock()
					if client == activeClient {
						client = nil
					}

					clientMu.Unlock()
					if event.Err != nil && !errors.Is(event.Err, net.ErrClosed) {
						fmt.Printf("\n[disconnected: %v]\n", event.Err)
					}
				}
			}
		}()
	}

	instanceIDs := func(_ string) []string {
		ids := make([]string, len(cachedInstances))
		for i, inst := range cachedInstances {
			ids[i] = inst.Id
		}
		return ids
	}

	providerIDs := func(_ string) []string {
		ids := make([]string, len(cachedProviders))
		for i, p := range cachedProviders {
			ids[i] = p.Uuid
		}
		return ids
	}

	clientOptions := func(priv, pub, server string) service.ClientOptions {
		return service.ClientOptions{PrivKey: priv, PubKey: pub, ServerKey: server}
	}

	if opts.serverAddr != "" {
		var err error
		client, err = service.NewClient("tcp", opts.serverAddr, clientOptions(opts.privKey, opts.pubKey, opts.serverKey))
		if err != nil {
			fmt.Println("Failed to connect:", err)
			client = nil
		} else {
			startWatcher(client)
			if opts.command == "" {
				fmt.Println("Successfully connected to", opts.serverAddr)
			}

			refreshIDs()
		}
	}

	if opts.unixSocket != "" {
		var err error
		client, err = service.NewClient("unix", resolve(opts.unixSocket), clientOptions(opts.privKey, opts.pubKey, opts.serverKey))
		if err != nil {
			fmt.Println("Failed to connect:", err)
			client = nil
		} else {
			startWatcher(client)
			if opts.command == "" {
				fmt.Println("Successfully connected to", opts.unixSocket)
			}

			refreshIDs()
		}
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("connect",
			readline.PcItem("tcp"),
			readline.PcItem("unix"),
		),
		readline.PcItem("disconnect"),
		readline.PcItem("list"),
		readline.PcItem("get", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("start-server"),
		readline.PcItem("start-client"),
		readline.PcItem("stop", readline.PcItemDynamic(instanceIDs, readline.PcItem("keep"))),
		readline.PcItem("delete-instance", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("restart", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("update-instance", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("list-providers"),
		readline.PcItem("add-provider"),
		readline.PcItem("get-provider", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("update-provider", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("delete-provider", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("validate-provider"),
		readline.PcItem("add-route", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("update-route", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("delete-route", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("list-routes", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("add-user", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("update-user", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("delete-user", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("list-users", readline.PcItemDynamic(providerIDs)),
		readline.PcItem("stats", readline.PcItemDynamic(instanceIDs, readline.PcItem("collect"))),
		readline.PcItem("sessions", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("kick-user", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("kick-session", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("validate-server"),
		readline.PcItem("validate-client"),
		readline.PcItem("convert"),
		readline.PcItem("logs",
			readline.PcItem("true"),
			readline.PcItem("false"),
		),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[34m> \033[0m",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer rl.Close()

	if opts.command == "" {
		fmt.Println("Welcome to Turnable Service CLI!")
		fmt.Println("Type \"help\" for a list of commands.")
	}

	first := true

	for {
		if opts.command != "" && !first {
			os.Exit(0)
		}

		first = false

		var input string
		if opts.command != "" {
			input = opts.command
		} else {
			input, err = rl.Readline()
			if errors.Is(err, readline.ErrInterrupt) || err == io.EOF {
				fmt.Println("Goodbye!")
				if c := getClient(); c != nil {
					_ = c.Close()
				}
				return nil
			}
		}

		parts, err := shlex.Split(input)
		if err != nil {
			if opts.command != "" {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("Failed to parse:", err)
			continue
		}

		if len(parts) < 1 {
			continue
		}

		switch parts[0] {
		case "connect":
			if len(parts) < 3 {
				fmt.Println("usage: connect <tcp/unix> <addr/path> [priv_key] [pub_key] [server_key]")
				continue
			}

			var addr string
			if parts[1] == "unix" {
				addr = resolve(parts[2])
			} else {
				addr = parts[2]
			}

			var priv, pub, serverKey string
			if len(parts) >= 5 {
				priv, pub = parts[3], parts[4]
			}

			if len(parts) >= 6 {
				serverKey = parts[5]
			}

			newClient, err := service.NewClient(parts[1], addr, clientOptions(priv, pub, serverKey))
			if err != nil {
				fmt.Println("Failed to connect:", err)
				continue
			}

			clientMu.Lock()
			if client != nil {
				_ = client.Close()
			}
			client = newClient
			clientMu.Unlock()

			startWatcher(newClient)
			fmt.Println("Successfully connected to", parts[2])
			refreshIDs()
		case "disconnect":
			clientMu.Lock()
			c := client
			client = nil
			clientMu.Unlock()

			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			cachedInstances = nil
			if err := c.Close(); err != nil {
				fmt.Println("Failed to disconnect:", err)
			} else {
				fmt.Println("Successfully disconnected")
			}
		case "list":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			instances, err := c.ListInstances()
			if err != nil {
				fmt.Println("Failed to list instances:", err)
				continue
			}

			if len(instances) == 0 {
				fmt.Println("No instances running")
				continue
			}

			for _, inst := range instances {
				typeName := "server"
				if inst.Type == pb.InstanceType_INSTANCE_TYPE_CLIENT {
					typeName = "client"
				}

				status := "unknown"
				switch inst.Status {
				case pb.InstanceStatus_INSTANCE_STATUS_UNSPECIFIED:
					status = "unspecified"
				case pb.InstanceStatus_INSTANCE_STATUS_STARTING:
					status = "starting"
				case pb.InstanceStatus_INSTANCE_STATUS_STARTED:
					status = "started"
				case pb.InstanceStatus_INSTANCE_STATUS_STOPPED:
					status = "stopped"
				case pb.InstanceStatus_INSTANCE_STATUS_FAILED:
					status = "failed"
				}

				name := inst.Name
				if name == "" {
					name = "Unnamed"
				}

				fmt.Printf("%-36s  type=%-6s  %-8s  name=%s\n",
					inst.Id, typeName, status, name)
			}

			cachedInstances = instances
		case "get":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: get <id>")
				continue
			}

			detail, err := c.GetInstance(parts[1])
			if err != nil {
				fmt.Println("Failed to get instance:", err)
				continue
			}

			typeName := "server"
			if detail.Info.Type == pb.InstanceType_INSTANCE_TYPE_CLIENT {
				typeName = "client"
			}

			status := "unknown"
			switch detail.Info.Status {
			case pb.InstanceStatus_INSTANCE_STATUS_UNSPECIFIED:
				status = "unspecified"
			case pb.InstanceStatus_INSTANCE_STATUS_STARTING:
				status = "starting"
			case pb.InstanceStatus_INSTANCE_STATUS_STARTED:
				status = "started"
			case pb.InstanceStatus_INSTANCE_STATUS_STOPPED:
				status = "stopped"
			case pb.InstanceStatus_INSTANCE_STATUS_FAILED:
				status = "failed"
			}

			fmt.Printf("ID:       %s\n", detail.Info.Id)
			fmt.Printf("Name:     %s\n", detail.Info.Name)
			fmt.Printf("Type:     %s\n", typeName)
			fmt.Printf("Status:   %s\n", status)
			fmt.Printf("Autostart: %t\n", detail.Info.Autostart)
			if len(detail.ListenAddrs) > 0 {
				fmt.Printf("Listen:   %s\n", strings.Join(detail.ListenAddrs, ", "))
			}

			fmt.Printf("Config:   %s\n", detail.Config)
		case "start-server":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: start-server <config_json|@file> <provider_uuid> [instance_id] [name] [autostart]")
				continue
			}

			var instanceID, name string
			if len(parts) >= 4 {
				instanceID = parts[3]
			}

			if len(parts) >= 5 {
				name = parts[4]
			}

			autostart, err := parseAutostart(parts)
			if err != nil {
				fmt.Println("Invalid autostart value:", err)
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			id, err := c.StartServer(configStr, instanceID, name, parts[2], autostart)
			if err != nil {
				fmt.Println("Failed to start server:", err)
				continue
			}

			fmt.Println("Started server instance:", id)
			refreshIDs()
		case "start-client":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: start-client <config_json_or_url|@file> <listen_addr> [instance_id] [name] [autostart]")
				continue
			}

			var instanceID, name string
			if len(parts) >= 4 {
				instanceID = parts[3]
			}
			if len(parts) >= 5 {
				name = parts[4]
			}

			autostart, err := parseAutostart(parts)
			if err != nil {
				fmt.Println("Invalid autostart value:", err)
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			id, err := c.StartClient(configStr, splitAddrs(parts[2]), instanceID, name, autostart)
			if err != nil {
				fmt.Println("Failed to start client:", err)
				continue
			}

			fmt.Println("Started client instance:", id)
			refreshIDs()
		case "stop", "delete-instance":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: stop <id> [keep] | delete-instance <id>")
				continue
			}

			keep := parts[0] == "stop" && len(parts) > 2 && parts[2] == "keep"
			stop := c.StopInstance
			if keep {
				stop = c.PauseInstance
			}

			if err := stop(parts[1]); err != nil {
				fmt.Println("Failed to stop instance:", err)
				continue
			}

			fmt.Println("Stopped instance:", parts[1])
			refreshIDs()
		case "restart":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: restart <id>")
				continue
			}

			if err := c.RestartInstance(parts[1]); err != nil {
				fmt.Println("Failed to restart instance:", err)
				continue
			}

			fmt.Println("Restarted instance:", parts[1])
		case "update-instance":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: update-instance <id> [name=<name>] [autostart=<true/false>] [config=<config|@file>] [listen=<addr,addr>]")
				continue
			}

			req, err := parseInstanceUpdate(parts[1], parts[2:])
			if err != nil {
				fmt.Println("Failed to update instance:", err)
				continue
			}

			if err := c.UpdateInstance(req); err != nil {
				fmt.Println("Failed to update instance:", err)
				continue
			}

			fmt.Println("Updated instance:", parts[1])
		case "validate-server":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: validate-server <config|@file>")
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			valid, err := c.ValidateServerConfig(configStr)
			if err != nil {
				fmt.Println("Invalid server config:", err)
				continue
			}

			if valid {
				fmt.Println("Server config is valid.")
			} else {
				fmt.Println("Server config is invalid.")
			}
		case "validate-client":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: validate-client <config|@file>")
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			valid, err := c.ValidateClientConfig(configStr)
			if err != nil {
				fmt.Println("Invalid client config:", err)
				continue
			}

			if valid {
				fmt.Println("Client config is valid.")
			} else {
				fmt.Println("Client config is invalid.")
			}
		case "convert":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: convert <config|@file>")
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			result, err := c.ConvertClientConfig(configStr)
			if err != nil {
				fmt.Println("Failed to convert config:", err)
				continue
			}

			fmt.Println(result)
		case "list-providers":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			providers, err := c.ListProviders()
			if err != nil {
				fmt.Println("Failed to list providers:", err)
				continue
			}

			if len(providers) == 0 {
				fmt.Println("No providers found")
			} else {
				fmt.Println("Available providers:")
				for _, p := range providers {
					fmt.Printf("  UUID: %s, Name: %s, In Use: %v\n", p.Uuid, p.Name, p.InUse)
				}
			}
		case "add-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 4 {
				fmt.Println("usage: add-provider <uuid> <name> <config|@file>")
				continue
			}

			configStr, err := loadConfig(parts[3])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			if err := c.AddProvider(parts[1], parts[2], configStr); err != nil {
				fmt.Println("Failed to add provider:", err)
				continue
			}

			fmt.Println("Added provider:", parts[1])
			refreshIDs()
		case "update-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: update-provider <uuid> [name=<name>] [config=<config|@file>]")
				continue
			}

			req, err := parseProviderUpdate(parts[1], parts[2:])
			if err != nil {
				fmt.Println("Failed to update provider:", err)
				continue
			}

			if err := c.UpdateProvider(req); err != nil {
				fmt.Println("Failed to update provider:", err)
				continue
			}

			fmt.Println("Updated provider:", parts[1])
			refreshIDs()
		case "get-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: get-provider <uuid>")
				continue
			}

			provider, err := c.GetProvider(parts[1])
			if err != nil {
				fmt.Println("Failed to get provider:", err)
				continue
			}

			fmt.Printf("UUID: %s\nName: %s\nIn Use: %v\nConfig: %s\n", provider.Uuid, provider.Name, provider.InUse, provider.Config)
		case "delete-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: delete-provider <uuid>")
				continue
			}

			if err := c.DeleteProvider(parts[1]); err != nil {
				fmt.Println("Failed to delete provider:", err)
				continue
			}

			fmt.Println("Deleted provider:", parts[1])
			refreshIDs()
		case "validate-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: validate-provider <config|@file>")
				continue
			}

			configStr, err := loadConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to load config:", err)
				continue
			}

			valid, err := c.ValidateProviderConfig(configStr)
			if err != nil {
				fmt.Println("Invalid provider config:", err)
				continue
			}

			if valid {
				fmt.Println("Provider config is valid.")
			} else {
				fmt.Println("Provider config is invalid.")
			}
		case "add-route", "update-route":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 4 {
				fmt.Printf("usage: %s <provider_uuid> <route_id> <address:port> [socket] [transport] [encryption] [name]\n", parts[0])
				continue
			}

			route, err := parseRoute(parts[2:])
			if err != nil {
				fmt.Println("Invalid route:", err)
				continue
			}

			if err := c.AddProviderRoute(parts[1], route); err != nil {
				fmt.Println("Failed to save provider route:", err)
				continue
			}

			fmt.Println("Saved route", parts[2], "in provider:", parts[1])
		case "delete-route":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: delete-route <provider_uuid> <route_id>")
				continue
			}

			err := c.DeleteProviderRoute(parts[1], parts[2])
			if err != nil {
				fmt.Println("Failed to delete provider route:", err)
				continue
			}

			fmt.Println("Deleted route", parts[2], "from provider:", parts[1])
		case "list-routes":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: list-routes <provider_uuid>")
				continue
			}

			routes, err := c.ListProviderRoutes(parts[1])
			if err != nil {
				fmt.Println("Failed to list provider routes:", err)
				continue
			}

			if len(routes) == 0 {
				fmt.Println("No routes in provider:", parts[1])
				continue
			}

			fmt.Printf("Routes in provider %s:\n", parts[1])
			for _, route := range routes {
				fmt.Printf("  %s: %s:%d (%s/%s)\n", route.Id, route.Address, route.Port, route.Socket, route.Transport)
			}
		case "add-user", "update-user":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Printf("usage: %s <provider_uuid> <user_uuid> [type] [peers] [allowed_routes] [forceturn]\n", parts[0])
				continue
			}

			user, err := parseUser(parts[2:])
			if err != nil {
				fmt.Println("Invalid user:", err)
				continue
			}

			if err := c.AddProviderUser(parts[1], user); err != nil {
				fmt.Println("Failed to save provider user:", err)
				continue
			}

			fmt.Println("Saved user", parts[2], "in provider:", parts[1])
		case "delete-user":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: delete-user <provider_uuid> <user_uuid>")
				continue
			}

			err := c.DeleteProviderUser(parts[1], parts[2])
			if err != nil {
				fmt.Println("Failed to delete provider user:", err)
				continue
			}

			fmt.Println("Deleted user", parts[2], "from provider:", parts[1])
		case "list-users":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: list-users <provider_uuid>")
				continue
			}

			users, err := c.ListProviderUsers(parts[1])
			if err != nil {
				fmt.Println("Failed to list provider users:", err)
				continue
			}

			if len(users) == 0 {
				fmt.Println("No users in provider:", parts[1])
				continue
			}

			fmt.Printf("Users in provider %s:\n", parts[1])
			for _, user := range users {
				fmt.Printf("  %s (type: %s, peers: %d)\n", user.Uuid, user.Type, user.Peers)
			}
		case "stats":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: stats <instance_id> [collect [ack_token]]")
				continue
			}

			collect := len(parts) > 2 && parts[2] == "collect"
			var stats *pb.GetStatsResponse
			var err error
			switch {
			case collect && len(parts) > 3:
				var ack uint64
				if ack, err = strconv.ParseUint(parts[3], 10, 64); err != nil {
					fmt.Println("Invalid ack token:", err)
					continue
				}

				stats, err = c.CollectStats(parts[1], ack)
			default:
				stats, err = c.GetStats(parts[1], collect)
			}

			if err != nil {
				fmt.Println("Failed to get stats:", err)
				continue
			}

			t := stats.Totals
			fmt.Printf("Instance %s: %d users online, %d sessions, %d tunnels, up %d B, down %d B\n",
				parts[1], t.Users, t.Sessions, t.Channels, t.Usage.Up, t.Usage.Down)
			for _, u := range stats.Users {
				fmt.Printf("  %s (online: %v, tunnels: %d, ips: %v) up %d B, down %d B\n",
					u.Uuid, u.Online, u.Channels, u.Ips, u.Usage.Up, u.Usage.Down)
			}

			for uuid, u := range stats.Collected {
				fmt.Printf("  collected %s: up %d B, down %d B\n", uuid, u.Up, u.Down)
			}

			if collect {
				fmt.Println("  collect token:", stats.CollectToken)
			}
		case "sessions":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: sessions <instance_id>")
				continue
			}

			sessions, err := c.ListSessions(parts[1])
			if err != nil {
				fmt.Println("Failed to list sessions:", err)
				continue
			}

			if len(sessions) == 0 {
				fmt.Println("No live sessions in instance:", parts[1])
				continue
			}

			for _, s := range sessions {
				fmt.Printf("  %s (user: %s, route: %s, from: %s, tunnels: %d) up %d B, down %d B\n",
					s.Id, s.UserUuid, s.RouteId, s.Addr, s.Channels, s.Usage.Up, s.Usage.Down)
			}
		case "kick-user", "kick-session":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Printf("usage: %s <instance_id> <%s>\n", parts[0], strings.TrimPrefix(parts[0], "kick-")+"_uuid")
				continue
			}

			var n int
			var err error
			if parts[0] == "kick-user" {
				n, err = c.KickUser(parts[1], parts[2])
			} else {
				n, err = c.KickSession(parts[1], parts[2])
			}

			if err != nil {
				fmt.Println("Failed to kick:", err)
				continue
			}

			fmt.Println("Closed", n, "tunnels")
		case "logs":
			if len(parts) < 2 {
				fmt.Println("usage: logs <true/false>")
				continue
			}
			switch parts[1] {
			case "true":
				logsEnabled = true
				fmt.Println("Log forwarding enabled.")
			case "false":
				logsEnabled = false
				fmt.Println("Log forwarding disabled.")
			default:
				fmt.Println("usage: logs <true/false>")
			}
		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  connect <tcp/unix> <addr> [priv_key] [pub_key] [server_key]    connect to service, server_key pins the service key")
			fmt.Println("  disconnect                                        close current connection")
			fmt.Println()
			fmt.Println("Instance Management:")
			fmt.Println("  list                                                       list all managed instances")
			fmt.Println("  get <id>                                                   get full details + config for an instance")
			fmt.Println("  start-server <config|@file> <provider_uuid> [id] [name] [autostart]    start a server instance")
			fmt.Println("  start-client <config|@file> <listen_addr> [id] [name] [autostart]      start a client instance")
			fmt.Println("  stop <id> [keep]                                           stop and remove an instance, keep leaves it stopped")
			fmt.Println("  delete-instance <id>                                       stop and remove an instance with its saved state")
			fmt.Println("  restart <id>                                               restart an instance, also revives stopped and failed ones")
			fmt.Println("  update-instance <id> [name=] [autostart=] [config=] [listen=]    change an instance, config and listen restart it")
			fmt.Println()
			fmt.Println("Provider Management:")
			fmt.Println("  list-providers                                list all managed providers")
			fmt.Println("  add-provider <uuid> <name> <config|@file>     add a new provider")
			fmt.Println("  get-provider <uuid>                           get provider details")
			fmt.Println("  delete-provider <uuid>                        delete a provider")
			fmt.Println("  update-provider <uuid> [name=] [config=]      rename a provider or reload it with a new config")
			fmt.Println("  validate-provider <config|@file>              validate a provider config")
			fmt.Println()
			fmt.Println("Provider Routes:")
			fmt.Println("  add-route <provider_uuid> <route_id> <address:port> [socket] [transport] [encryption] [name]")
			fmt.Println("  update-route <provider_uuid> <route_id> <address:port> [socket] [transport] [encryption] [name]")
			fmt.Println("                                         add or replace a route, defaults: udp none handshake")
			fmt.Println("  delete-route <provider_uuid> <route_id>                remove a route from a provider")
			fmt.Println("  list-routes <provider_uuid>                            list routes in a provider")
			fmt.Println()
			fmt.Println("Provider Users:")
			fmt.Println("  add-user <provider_uuid> <user_uuid> [type] [peers] [allowed_routes] [forceturn]")
			fmt.Println("  update-user <provider_uuid> <user_uuid> [type] [peers] [allowed_routes] [forceturn]")
			fmt.Println("                                             add or replace a user, defaults: client 1, routes comma separated")
			fmt.Println("  delete-user <provider_uuid> <user_uuid>    remove a user from a provider")
			fmt.Println("  list-users <provider_uuid>                 list users in a provider")
			fmt.Println()
			fmt.Println("Stats & Control:")
			fmt.Println("  stats <id> [collect [ack]]        server totals and users, collect also returns usage since the last collect")
			fmt.Println("                                    with ack, a batch repeats until acked with its collect token")
			fmt.Println("  sessions <id>                     list live sessions")
			fmt.Println("  kick-user <id> <user_uuid>        close all tunnels of a user")
			fmt.Println("  kick-session <id> <session_id>    close all tunnels of a session")
			fmt.Println()
			fmt.Println("Validation & Conversion:")
			fmt.Println("  validate-server <config|@file>   validate a server config")
			fmt.Println("  validate-client <config|@file>   validate a client config")
			fmt.Println("  convert <config|@file>           convert config between JSON and URL")
			fmt.Println()
			fmt.Println("Other:")
			fmt.Println("  logs <true/false>   toggle server log forwarding")
			fmt.Println("  help                show this help")
			fmt.Println("  exit / quit         exit the CLI")
		case "exit", "quit":
			fmt.Println("Goodbye!")
			if c := getClient(); c != nil {
				return c.Close()
			}
			return nil
		default:
			fmt.Println("Unknown command. Type \"help\" for help.")
		}
	}
}

// parseRoute builds a route from <route_id> <address:port> [socket] [transport] [encryption] [name]
func parseRoute(args []string) (*pb.RouteInfo, error) {
	host, portStr, err := net.SplitHostPort(args[1])
	if err != nil {
		return nil, fmt.Errorf("address must be <address:port>: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port number %q", portStr)
	}

	route := &pb.RouteInfo{
		Id:         args[0],
		Address:    host,
		Port:       int32(port),
		Socket:     "udp",
		Transport:  "none",
		Encryption: "handshake",
		Name:       args[0],
	}

	for i, dst := range []*string{&route.Socket, &route.Transport, &route.Encryption, &route.Name} {
		if len(args) > i+2 {
			*dst = args[i+2]
		}
	}

	return route, nil
}

// parseUser builds a user from <user_uuid> [type] [peers] [allowed_routes] [forceturn]
func parseUser(args []string) (*pb.UserInfo, error) {
	user := &pb.UserInfo{Uuid: args[0], Type: "client", Peers: 1}

	if len(args) > 1 {
		user.Type = args[1]
	}

	if len(args) > 2 {
		peers, err := strconv.Atoi(args[2])
		if err != nil {
			return nil, fmt.Errorf("invalid peers %q", args[2])
		}
		user.Peers = int32(peers)
	}

	if len(args) > 3 {
		user.AllowedRoutes = splitAddrs(args[3])
	}

	if len(args) > 4 {
		forceTurn, err := strconv.ParseBool(args[4])
		if err != nil {
			return nil, fmt.Errorf("invalid forceturn %q", args[4])
		}
		user.Forceturn = forceTurn
	}

	return user, nil
}

// splitOptions splits key=value arguments into a map
func splitOptions(args []string) (map[string]string, error) {
	opts := make(map[string]string, len(args))
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not key=value", a)
		}

		opts[k] = v
	}

	return opts, nil
}

// parseInstanceUpdate builds an instance update from key=value arguments
func parseInstanceUpdate(id string, args []string) (*pb.UpdateInstanceRequest, error) {
	opts, err := splitOptions(args)
	if err != nil {
		return nil, err
	}

	req := &pb.UpdateInstanceRequest{InstanceId: id}
	for k, v := range opts {
		switch k {
		case "name":
			req.Name = &v
		case "autostart":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("invalid autostart %q", v)
			}
			req.Autostart = &b
		case "config":
			cfg, err := loadConfig(v)
			if err != nil {
				return nil, err
			}
			req.Config = &cfg
		case "listen":
			req.ListenAddrs = splitAddrs(v)
		default:
			return nil, fmt.Errorf("unknown option %q", k)
		}
	}

	return req, nil
}

// parseProviderUpdate builds a provider update from key=value arguments
func parseProviderUpdate(uuid string, args []string) (*pb.UpdateProviderRequest, error) {
	opts, err := splitOptions(args)
	if err != nil {
		return nil, err
	}

	req := &pb.UpdateProviderRequest{Uuid: uuid}
	for k, v := range opts {
		switch k {
		case "name":
			req.Name = &v
		case "config":
			cfg, err := loadConfig(v)
			if err != nil {
				return nil, err
			}
			req.Config = &cfg
		default:
			return nil, fmt.Errorf("unknown option %q", k)
		}
	}

	return req, nil
}
