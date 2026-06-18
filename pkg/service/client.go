package service

import (
	"fmt"
	"net"
	"sync"

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
)

// Event is emitted by the client read loop to signal logs, instance events, or disconnects
type Event struct {
	Kind          EventKind
	Log           *pb.LogRecord
	InstanceEvent *pb.InstanceEvent
	Err           error
}

// Client communicates with a Turnable service server over a custom protocol
type Client struct {
	conn    net.Conn
	writeMu sync.Mutex
	respCh  chan *pb.Response
	eventCh chan Event
	done    chan struct{}
}

// NewClient connects to a remote Turnable service server
func NewClient(network, addr string, clientPrivB64, clientPubB64 string) (*Client, error) {
	nc, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	var kp *KeyPair
	if clientPrivB64 != "" || clientPubB64 != "" {
		kp, err = NewKeyPair(clientPubB64, clientPrivB64)
		if err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("parse client keypair: %w", err)
		}
	}

	wrapped, err := clientHandshake(nc, kp)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}

	c := &Client{
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
		case resp.GetError() != nil:
			select {
			case c.eventCh <- Event{Kind: EventDisconnected, Err: fmt.Errorf("%s", resp.GetError().Message)}:
			default:
			}
			close(c.eventCh)
			return
		default:
			c.respCh <- &resp
		}
	}
}

// sendRequest sends a proto request and waits for a response via the read loop
func (c *Client) sendRequest(req *pb.Request) (*pb.Response, error) {
	c.writeMu.Lock()
	err := writeFramed(c.conn, req)
	c.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	select {
	case resp := <-c.respCh:
		return resp, nil
	case <-c.done:
		return nil, fmt.Errorf("connection closed")
	}
}

// StartServer requests a new server instance with a provider UUID
func (c *Client) StartServer(config, instanceID, name, providerUUID string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartServer{
			StartServer: &pb.StartServerRequest{
				Config:       config,
				InstanceId:   instanceID,
				Name:         name,
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
func (c *Client) StartClient(config string, listenAddrs []string, instanceID, name string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartClient{
			StartClient: &pb.StartClientRequest{
				Config:      config,
				ListenAddrs: listenAddrs,
				InstanceId:  instanceID,
				Name:        name,
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

// StopInstance requests to stop an instance
func (c *Client) StopInstance(instanceID string) error {
	req := &pb.Request{
		Payload: &pb.Request_StopInstance{
			StopInstance: &pb.StopInstanceRequest{
				InstanceId: instanceID,
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
