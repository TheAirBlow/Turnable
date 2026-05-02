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
	configPath string
	persistDir string
	verbose    bool
}

// serviceServerOptions holds CLI flags for the service server subcommand
type serviceClientOptions struct {
	unixSocket string
	serverAddr string
	privKey    string
	pubKey     string
	command    string
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

// newServiceServerCommand creates the generate config cobra command
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
	return cmd
}

// newServiceClientCommand creates the generate config cobra command
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
	cmd.Flags().StringVarP(&opts.pubKey, "pub-key", "p", "", "public ML-KEM-768 key for auth")
	cmd.Flags().StringVarP(&opts.privKey, "priv-key", "k", "", "private ML-KEM-768 key for auth")
	return cmd
}

// serviceServerMain runs the config command
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
		server.SetPersistDir(resolve(opts.persistDir))
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

// serviceClientMain runs the service CLI REPL
func serviceClientMain(opts *serviceClientOptions) error {
	if opts.serverAddr != "" && opts.unixSocket != "" {
		return errors.New("only one of --address or --unix can be set")
	}

	var clientMu sync.Mutex
	var client *service.Client
	var cachedInstances []*pb.InstanceInfo
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
		instances, err := c.ListInstances()
		if err != nil {
			return
		}
		cachedInstances = instances
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

	if opts.serverAddr != "" {
		var err error
		client, err = service.NewClient("tcp", opts.serverAddr, opts.pubKey, opts.privKey)
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
		client, err = service.NewClient("unix", resolve(opts.unixSocket), opts.pubKey, opts.privKey)
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
		readline.PcItem("stop", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("update-provider", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("add-route", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("delete-route", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("add-user", readline.PcItemDynamic(instanceIDs)),
		readline.PcItem("delete-user", readline.PcItemDynamic(instanceIDs)),
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
				fmt.Println("usage: connect <tcp/unix> <addr/path> [priv_key] [pub_key]")
				continue
			}

			var addr string
			if parts[1] == "unix" {
				addr = resolve(parts[2])
			} else {
				addr = parts[2]
			}

			var newClient *service.Client
			if len(parts) < 5 {
				newClient, err = service.NewClient(parts[1], addr, "", "")
			} else {
				newClient, err = service.NewClient(parts[1], addr, parts[3], parts[4])
			}

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

			if len(parts) < 2 {
				fmt.Println("usage: start-server <config_json> [instance_id] [name]")
				continue
			}

			var instanceID, name string
			if len(parts) >= 3 {
				instanceID = parts[2]
			}

			if len(parts) >= 4 {
				name = parts[3]
			}

			id, err := c.StartServer(parts[1], instanceID, name)
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
				fmt.Println("usage: start-client <config_json_or_url> <listen_addr> [instance_id] [name]")
				continue
			}

			var instanceID, name string
			if len(parts) >= 4 {
				instanceID = parts[3]
			}
			if len(parts) >= 5 {
				name = parts[4]
			}

			id, err := c.StartClient(parts[1], splitAddrs(parts[2]), instanceID, name)
			if err != nil {
				fmt.Println("Failed to start client:", err)
				continue
			}

			fmt.Println("Started client instance:", id)
			refreshIDs()
		case "stop":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: stop <id>")
				continue
			}

			if err := c.StopInstance(parts[1]); err != nil {
				fmt.Println("Failed to stop instance:", err)
				continue
			}

			fmt.Println("Stopped instance:", parts[1])
			refreshIDs()
		case "update-provider":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: update-provider <id> <config>")
				continue
			}

			if err := c.UpdateProvider(parts[1], parts[2]); err != nil {
				fmt.Println("Failed to update provider:", err)
				continue
			}

			fmt.Println("Updated provider for instance:", parts[1])
		case "add-route":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: add-route <instance_id> <route_json>")
				continue
			}

			if err := c.AddRoute(parts[1], parts[2]); err != nil {
				fmt.Println("Failed to add route:", err)
				continue
			}

			fmt.Println("Added/updated route on instance:", parts[1])
		case "delete-route":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: delete-route <instance_id> <route_id>")
				continue
			}

			if err := c.DeleteRoute(parts[1], parts[2]); err != nil {
				fmt.Println("Failed to delete route:", err)
				continue
			}

			fmt.Println("Deleted route", parts[2], "from instance:", parts[1])
		case "add-user":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: add-user <instance_id> <user_json>")
				continue
			}

			if err := c.AddUser(parts[1], parts[2]); err != nil {
				fmt.Println("Failed to add user:", err)
				continue
			}

			fmt.Println("Added/updated user on instance:", parts[1])
		case "delete-user":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 3 {
				fmt.Println("usage: delete-user <instance_id> <user_uuid>")
				continue
			}

			if err := c.DeleteUser(parts[1], parts[2]); err != nil {
				fmt.Println("Failed to delete user:", err)
				continue
			}

			fmt.Println("Deleted user", parts[2], "from instance:", parts[1])
		case "validate-server":
			c := getClient()
			if c == nil {
				fmt.Println("Not currently connected to a server")
				continue
			}

			if len(parts) < 2 {
				fmt.Println("usage: validate-server <config>")
				continue
			}

			valid, err := c.ValidateServerConfig(parts[1])
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
				fmt.Println("usage: validate-client <config>")
				continue
			}

			valid, err := c.ValidateClientConfig(parts[1])
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
				fmt.Println("usage: convert <config>")
				continue
			}

			result, err := c.ConvertClientConfig(parts[1])
			if err != nil {
				fmt.Println("Failed to convert config:", err)
				continue
			}

			fmt.Println(result)
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
			fmt.Println("  connect <tcp/unix> <addr> [priv_key] [pub_key]              connect to service")
			fmt.Println("  disconnect                                                  close current connection")
			fmt.Println("  list                                                        list all managed instances")
			fmt.Println("  get <id>                                                    get full details + config for an instance")
			fmt.Println("  start-server <config_json> [id] [name]                      start a server instance")
			fmt.Println("  start-client <config_json_or_url> <listen_addr> [id] [name] start a client instance")
			fmt.Println("  stop <id>                                                   stop an instance")
			fmt.Println("  update-provider <id> <config>                               update provider config")
			fmt.Println("  add-route <id> <route_json>                                 add or update a route on a server instance")
			fmt.Println("  delete-route <id> <route_id>                                remove a route from a server instance")
			fmt.Println("  add-user <id> <user_json>                                   add or update a user on a server instance")
			fmt.Println("  delete-user <id> <user_uuid>                                remove a user from a server instance")
			fmt.Println("  validate-server <config>                                    validate a server config")
			fmt.Println("  validate-client <config>                                    validate a client config")
			fmt.Println("  convert <config>                                            convert config between JSON and URL")
			fmt.Println("  logs <true/false>                                           toggle server log forwarding")
			fmt.Println("  help                                                        show this help")
			fmt.Println("  exit / quit                                                 exit the CLI")
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
