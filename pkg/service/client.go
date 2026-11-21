package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// EventKind represents a service client event type
type EventKind int

const (
	EventLog             EventKind = iota // server emitted a log record
	EventDisconnected                     // connection was lost or closed
	EventInstanceCreated                  // an instance was created
	EventInstanceStarted                  // an instance was started
	EventInstanceStopped                  // an instance was stopped
	EventInstanceFailed                   // an instance failed to start
	EventInstanceUpdated                  // an instance was updated
	EventSession                          // a tunnel of a server instance opened or closed
)

// Event is emitted by the client read loop to signal logs, instance events, or disconnects
type Event struct {
	Kind          EventKind         // event kind
	Log           *pb.LogRecord     // log record, for log events
	InstanceEvent *pb.InstanceEvent // instance event, for instance events
	SessionEvent  *pb.SessionEvent  // session event, for session events
	Err           error             // error, for error events
}

// defaultRequestTimeout is how long a request may wait for its response
const defaultRequestTimeout = 30 * time.Second

// ClientOptions holds the connection and auth settings of a service client
type ClientOptions struct {
	PrivKey   string        // client private key, base64
	PubKey    string        // client public key, base64
	ServerKey string        // pinned service public key, base64, optional
	Timeout   time.Duration // request timeout, defaults to 30 seconds
}

// Client communicates with a Turnable service server over a custom protocol
type Client struct {
	conn    net.Conn          // connection to the service
	reqMu   sync.Mutex        // serializes requests
	respCh  chan *pb.Response // responses to requests
	eventCh chan Event        // pushed events
	done    chan struct{}     // closed when the connection ends
	timeout time.Duration     // request timeout
	nextID  uint64            // last request ID handed out, guarded by reqMu
	pending atomic.Uint64     // ID of the request awaiting a response

	errMu    sync.Mutex // guards closeErr
	closeErr error      // reason the service ended the connection
}

// NewClient connects to a remote Turnable service server
func NewClient(network, addr string, opts ClientOptions) (*Client, error) {
	var kp *KeyPair
	if opts.PrivKey != "" || opts.PubKey != "" {
		var err error
		kp, err = NewKeyPair(opts.PubKey, opts.PrivKey)
		if err != nil {
			return nil, fmt.Errorf("parse client keypair: %w", err)
		}
	}

	var serverPub []byte
	if opts.ServerKey != "" {
		var err error
		serverPub, err = base64.StdEncoding.DecodeString(opts.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("decode server key: %w", err)
		}
	}

	nc, err := net.DialTimeout(network, addr, handshakeTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	wrapped, err := clientHandshake(nc, kp, serverPub)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	c := &Client{
		timeout: timeout,
		conn:    wrapped,
		respCh:  make(chan *pb.Response, 1),
		eventCh: make(chan Event, 256),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Close closes the client connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// WatchEvents returns a channel that receives events from the server
func (c *Client) WatchEvents() <-chan Event {
	return c.eventCh
}

// readLoop demuxes incoming frames into responses and logs/errors
func (c *Client) readLoop() {
	defer close(c.done)
	for {
		var resp pb.Response
		if err := readFramed(c.conn, &resp); err != nil {
			select {
			case c.eventCh <- Event{Kind: EventDisconnected, Err: err}:
			default:
			}
			close(c.eventCh)
			return
		}

		switch {
		case resp.GetLogRecord() != nil:
			select {
			case c.eventCh <- Event{Kind: EventLog, Log: resp.GetLogRecord()}:
			default:
			}
		case resp.GetInstanceEvent() != nil:
			ev := resp.GetInstanceEvent()

			var kind EventKind
			switch ev.EventType {
			case pb.InstanceEventType_INSTANCE_EVENT_TYPE_CREATED:
				kind = EventInstanceCreated
			case pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED:
				kind = EventInstanceStarted
			case pb.InstanceEventType_INSTANCE_EVENT_TYPE_STOPPED:
				kind = EventInstanceStopped
			case pb.InstanceEventType_INSTANCE_EVENT_TYPE_FAILED:
				kind = EventInstanceFailed
			case pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED:
				kind = EventInstanceUpdated
			default:
				kind = EventLog
			}

			select {
			case c.eventCh <- Event{Kind: kind, InstanceEvent: ev}:
			default:
			}
		case resp.GetSessionEvent() != nil:
			select {
			case c.eventCh <- Event{Kind: EventSession, SessionEvent: resp.GetSessionEvent()}:
			default:
			}
		case resp.GetError() != nil:
			c.setCloseErr(fmt.Errorf("%s", resp.GetError().Message))
			select {
			case c.eventCh <- Event{Kind: EventDisconnected, Err: fmt.Errorf("%s", resp.GetError().Message)}:
			default:
			}
			close(c.eventCh)
			return
		default:
			// A reply to a request that already timed out is dropped
			if id := c.pending.Load(); id != 0 && resp.RequestId == id {
				select {
				case c.respCh <- &resp:
				default:
				}
			}
		}
	}
}

// setCloseErr remembers why the service ended the connection
func (c *Client) setCloseErr(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	c.closeErr = err
}

// closedError returns the reason the connection ended
func (c *Client) closedError() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.closeErr != nil {
		return fmt.Errorf("connection closed: %w", c.closeErr)
	}
	return errors.New("connection closed")
}

// sendRequest sends a proto request and waits for the response carrying its ID
func (c *Client) sendRequest(req *pb.Request) (*pb.Response, error) {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	c.nextID++
	req.RequestId = c.nextID
	c.pending.Store(req.RequestId)
	defer c.pending.Store(0)

	select {
	case <-c.respCh:
	default:
	}

	if err := writeFramed(c.conn, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()

	select {
	case resp := <-c.respCh:
		return resp, nil
	case <-c.done:
		return nil, c.closedError()
	case <-timer.C:
		return nil, fmt.Errorf("request timed out after %s", c.timeout)
	}
}

// StartServer requests a new server instance with a provider UUID
func (c *Client) StartServer(config, instanceID, name, providerUUID string, autostart bool) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartServer{
			StartServer: &pb.StartServerRequest{
				Config:       config,
				InstanceId:   instanceID,
				Name:         name,
				Autostart:    autostart,
				ProviderUuid: providerUUID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return "", err
	}

	if sr := resp.GetStartServer(); sr != nil {
		if sr.Error != "" {
			return "", fmt.Errorf("start server: %s", sr.Error)
		}
		return sr.InstanceId, nil
	}

	return "", fmt.Errorf("unexpected response type")
}

// StartClient requests a new client instance
func (c *Client) StartClient(config string, listenAddrs []string, instanceID, name string, autostart bool) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartClient{
			StartClient: &pb.StartClientRequest{
				Config:      config,
				ListenAddrs: listenAddrs,
				InstanceId:  instanceID,
				Name:        name,
				Autostart:   autostart,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return "", err
	}

	if sr := resp.GetStartClient(); sr != nil {
		if sr.Error != "" {
			return "", fmt.Errorf("start client: %s", sr.Error)
		}
		return sr.InstanceId, nil
	}

	return "", fmt.Errorf("unexpected response type")
}

// StopInstance stops and removes an instance together with its persisted record
func (c *Client) StopInstance(instanceID string) error {
	return c.stopInstance(instanceID, false)
}

// PauseInstance stops an instance but keeps it listed and persisted so it can be restarted
func (c *Client) PauseInstance(instanceID string) error {
	return c.stopInstance(instanceID, true)
}

// stopInstance sends a stop request
func (c *Client) stopInstance(instanceID string, keep bool) error {
	req := &pb.Request{
		Payload: &pb.Request_StopInstance{
			StopInstance: &pb.StopInstanceRequest{
				InstanceId: instanceID,
				Keep:       keep,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if sr := resp.GetStopInstance(); sr != nil {
		if sr.Error != "" {
			return fmt.Errorf("stop instance: %s", sr.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// RestartInstance restarts an instance from its stored config, which also revives stopped and failed ones
func (c *Client) RestartInstance(instanceID string) error {
	resp, err := c.sendRequest(&pb.Request{Payload: &pb.Request_RestartInstance{
		RestartInstance: &pb.RestartInstanceRequest{InstanceId: instanceID},
	}})
	if err != nil {
		return err
	}

	if rr := resp.GetRestartInstance(); rr != nil {
		if rr.Error != "" {
			return fmt.Errorf("restart instance: %s", rr.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// UpdateInstance changes an instance, nil fields are left alone and a changed config or listen address list restarts it
func (c *Client) UpdateInstance(req *pb.UpdateInstanceRequest) error {
	resp, err := c.sendRequest(&pb.Request{Payload: &pb.Request_UpdateInstance{UpdateInstance: req}})
	if err != nil {
		return err
	}

	if ur := resp.GetUpdateInstance(); ur != nil {
		if ur.Error != "" {
			return fmt.Errorf("update instance: %s", ur.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// ListInstances requests the list of all instances (config is not included)
func (c *Client) ListInstances() ([]*pb.InstanceInfo, error) {
	req := &pb.Request{
		Payload: &pb.Request_ListInstances{
			ListInstances: &pb.ListInstancesRequest{},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if lr := resp.GetListInstances(); lr != nil {
		return lr.Instances, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// GetInstance requests the full details of a single instance
func (c *Client) GetInstance(instanceID string) (*pb.GetInstanceResponse, error) {
	req := &pb.Request{
		Payload: &pb.Request_GetInstance{
			GetInstance: &pb.GetInstanceRequest{
				InstanceId: instanceID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if gr := resp.GetGetInstance(); gr != nil {
		if gr.Error != "" {
			return nil, fmt.Errorf("get instance: %s", gr.Error)
		}
		return gr, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// ValidateServerConfig requests server config validation
func (c *Client) ValidateServerConfig(config string) (bool, error) {
	req := &pb.Request{
		Payload: &pb.Request_ValidateServerConfig{
			ValidateServerConfig: &pb.ValidateServerConfigRequest{
				Config: config,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return false, err
	}

	if vr := resp.GetValidateServerConfig(); vr != nil {
		if !vr.Valid && vr.Error != "" {
			return false, fmt.Errorf("validate server config: %s", vr.Error)
		}
		return vr.Valid, nil
	}

	return false, fmt.Errorf("unexpected response type")
}

// ValidateClientConfig requests client config validation
func (c *Client) ValidateClientConfig(config string) (bool, error) {
	req := &pb.Request{
		Payload: &pb.Request_ValidateClientConfig{
			ValidateClientConfig: &pb.ValidateClientConfigRequest{
				Config: config,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return false, err
	}

	if vr := resp.GetValidateClientConfig(); vr != nil {
		if !vr.Valid && vr.Error != "" {
			return false, fmt.Errorf("validate client config: %s", vr.Error)
		}
		return vr.Valid, nil
	}

	return false, fmt.Errorf("unexpected response type")
}

// ConvertClientConfig requests client config format conversion
func (c *Client) ConvertClientConfig(config string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_ConvertClientConfig{
			ConvertClientConfig: &pb.ConvertClientConfigRequest{
				Config: config,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return "", err
	}

	if cr := resp.GetConvertClientConfig(); cr != nil {
		if cr.Error != "" {
			return "", fmt.Errorf("convert client config: %s", cr.Error)
		}
		return cr.Config, nil
	}

	return "", fmt.Errorf("unexpected response type")
}

// AddProvider adds a new managed provider
func (c *Client) AddProvider(uuid, name, config string) error {
	req := &pb.Request{
		Payload: &pb.Request_AddProvider{
			AddProvider: &pb.AddProviderRequest{
				Uuid:   uuid,
				Name:   name,
				Config: config,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if ap := resp.GetAddProvider(); ap != nil {
		if ap.Error != "" {
			return fmt.Errorf("add provider: %s", ap.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// UpdateProvider renames a provider or reloads it with a new config, nil fields are left alone
func (c *Client) UpdateProvider(req *pb.UpdateProviderRequest) error {
	resp, err := c.sendRequest(&pb.Request{Payload: &pb.Request_UpdateProvider{UpdateProvider: req}})
	if err != nil {
		return err
	}

	if up := resp.GetUpdateProvider(); up != nil {
		if up.Error != "" {
			return fmt.Errorf("update provider: %s", up.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// GetProvider retrieves a managed provider by UUID
func (c *Client) GetProvider(uuid string) (*pb.ProviderInfo, error) {
	req := &pb.Request{
		Payload: &pb.Request_GetProvider{
			GetProvider: &pb.GetProviderRequest{
				Uuid: uuid,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if gp := resp.GetGetProvider(); gp != nil {
		if gp.Error != "" {
			return nil, fmt.Errorf("get provider: %s", gp.Error)
		}
		return gp.Provider, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// ListProviders retrieves all managed providers
func (c *Client) ListProviders() ([]*pb.ProviderInfo, error) {
	req := &pb.Request{
		Payload: &pb.Request_ListProviders{
			ListProviders: &pb.ListProvidersRequest{},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if lp := resp.GetListProviders(); lp != nil {
		return lp.Providers, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// DeleteProvider removes a managed provider by UUID
func (c *Client) DeleteProvider(uuid string) error {
	req := &pb.Request{
		Payload: &pb.Request_DeleteProvider{
			DeleteProvider: &pb.DeleteProviderRequest{
				Uuid: uuid,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if dp := resp.GetDeleteProvider(); dp != nil {
		if dp.Error != "" {
			return fmt.Errorf("delete provider: %s", dp.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// ValidateProviderConfig validates a provider config
func (c *Client) ValidateProviderConfig(config string) (bool, error) {
	req := &pb.Request{
		Payload: &pb.Request_ValidateProviderConfig{
			ValidateProviderConfig: &pb.ValidateProviderConfigRequest{
				Config: config,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return false, err
	}

	if vp := resp.GetValidateProviderConfig(); vp != nil {
		if !vp.Valid && vp.Error != "" {
			return false, fmt.Errorf("validate provider config: %s", vp.Error)
		}
		return vp.Valid, nil
	}

	return false, fmt.Errorf("unexpected response type")
}

// AddProviderRoute adds a route to a provider
func (c *Client) AddProviderRoute(providerUUID string, route *pb.RouteInfo) error {
	req := &pb.Request{
		Payload: &pb.Request_AddProviderRoute{
			AddProviderRoute: &pb.AddProviderRouteRequest{
				ProviderUuid: providerUUID,
				Route:        route,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if ar := resp.GetAddProviderRoute(); ar != nil {
		if ar.Error != "" {
			return fmt.Errorf("add provider route: %s", ar.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// DeleteProviderRoute removes a route from a provider
func (c *Client) DeleteProviderRoute(providerUUID string, routeID string) error {
	req := &pb.Request{
		Payload: &pb.Request_DeleteProviderRoute{
			DeleteProviderRoute: &pb.DeleteProviderRouteRequest{
				ProviderUuid: providerUUID,
				RouteId:      routeID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if dr := resp.GetDeleteProviderRoute(); dr != nil {
		if dr.Error != "" {
			return fmt.Errorf("delete provider route: %s", dr.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// ListProviderRoutes lists all routes from a provider
func (c *Client) ListProviderRoutes(providerUUID string) ([]*pb.RouteInfo, error) {
	req := &pb.Request{
		Payload: &pb.Request_ListProviderRoutes{
			ListProviderRoutes: &pb.ListProviderRoutesRequest{
				ProviderUuid: providerUUID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if lr := resp.GetListProviderRoutes(); lr != nil {
		if lr.Error != "" {
			return nil, fmt.Errorf("list provider routes: %s", lr.Error)
		}
		return lr.Routes, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// AddProviderUser adds a user to a provider
func (c *Client) AddProviderUser(providerUUID string, user *pb.UserInfo) error {
	req := &pb.Request{
		Payload: &pb.Request_AddProviderUser{
			AddProviderUser: &pb.AddProviderUserRequest{
				ProviderUuid: providerUUID,
				User:         user,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if au := resp.GetAddProviderUser(); au != nil {
		if au.Error != "" {
			return fmt.Errorf("add provider user: %s", au.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// DeleteProviderUser removes a user from a provider
func (c *Client) DeleteProviderUser(providerUUID string, userUUID string) error {
	req := &pb.Request{
		Payload: &pb.Request_DeleteProviderUser{
			DeleteProviderUser: &pb.DeleteProviderUserRequest{
				ProviderUuid: providerUUID,
				UserUuid:     userUUID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if du := resp.GetDeleteProviderUser(); du != nil {
		if du.Error != "" {
			return fmt.Errorf("delete provider user: %s", du.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// ListProviderUsers lists all users from a provider
func (c *Client) ListProviderUsers(providerUUID string) ([]*pb.UserInfo, error) {
	req := &pb.Request{
		Payload: &pb.Request_ListProviderUsers{
			ListProviderUsers: &pb.ListProviderUsersRequest{
				ProviderUuid: providerUUID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if lu := resp.GetListProviderUsers(); lu != nil {
		if lu.Error != "" {
			return nil, fmt.Errorf("list provider users: %s", lu.Error)
		}
		return lu.Users, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// GetStats fetches a server instance's stats; collect also returns per-user usage since the last collect and resets the counters
func (c *Client) GetStats(instanceID string, collect bool) (*pb.GetStatsResponse, error) {
	return c.getStats(&pb.GetStatsRequest{InstanceId: instanceID, Collect: collect})
}

// getStats sends a stats request
func (c *Client) getStats(sr *pb.GetStatsRequest) (*pb.GetStatsResponse, error) {
	resp, err := c.sendRequest(&pb.Request{Payload: &pb.Request_GetStats{GetStats: sr}})
	if err != nil {
		return nil, err
	}

	if gs := resp.GetGetStats(); gs != nil {
		if gs.Error != "" {
			return nil, fmt.Errorf("get stats: %s", gs.Error)
		}
		return gs, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// CollectStats fetches stats like GetStats with collect set, but keeps returning the same usage until it is confirmed.
// ack is the CollectToken of the last batch the caller processed, or 0 when there is none.
func (c *Client) CollectStats(instanceID string, ack uint64) (*pb.GetStatsResponse, error) {
	return c.getStats(&pb.GetStatsRequest{InstanceId: instanceID, Collect: true, AckToken: &ack})
}

// ListSessions lists the live sessions of a server instance
func (c *Client) ListSessions(instanceID string) ([]*pb.SessionStats, error) {
	req := &pb.Request{
		Payload: &pb.Request_ListSessions{
			ListSessions: &pb.ListSessionsRequest{
				InstanceId: instanceID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if ls := resp.GetListSessions(); ls != nil {
		if ls.Error != "" {
			return nil, fmt.Errorf("list sessions: %s", ls.Error)
		}
		return ls.Sessions, nil
	}

	return nil, fmt.Errorf("unexpected response type")
}

// KickUser closes every tunnel of a user on a server instance and returns how many it closed
func (c *Client) KickUser(instanceID, userUUID string) (int, error) {
	return c.kick(&pb.KickRequest{InstanceId: instanceID, UserUuid: userUUID})
}

// KickSession closes every tunnel of a session on a server instance and returns how many it closed
func (c *Client) KickSession(instanceID, sessionID string) (int, error) {
	return c.kick(&pb.KickRequest{InstanceId: instanceID, SessionId: sessionID})
}

// kick sends a kick request
func (c *Client) kick(kr *pb.KickRequest) (int, error) {
	resp, err := c.sendRequest(&pb.Request{Payload: &pb.Request_Kick{Kick: kr}})
	if err != nil {
		return 0, err
	}

	if k := resp.GetKick(); k != nil {
		if k.Error != "" {
			return 0, fmt.Errorf("kick: %s", k.Error)
		}
		return int(k.Kicked), nil
	}

	return 0, fmt.Errorf("unexpected response type")
}
