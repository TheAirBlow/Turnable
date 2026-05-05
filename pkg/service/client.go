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

// StartServer requests a new server instance
func (c *Client) StartServer(config, instanceID, name string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartServer{
			StartServer: &pb.StartServerRequest{
				Config:     config,
				InstanceId: instanceID,
				Name:       name,
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

// UpdateProvider requests to update a provider config
func (c *Client) UpdateProvider(instanceID string, cfg string) error {
	req := &pb.Request{
		Payload: &pb.Request_UpdateProvider{
			UpdateProvider: &pb.UpdateProviderRequest{
				InstanceId:     instanceID,
				ProviderConfig: cfg,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if resp.GetUpdateProvider() != nil {
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

// AddRoute adds or updates a route on a server instance
func (c *Client) AddRoute(instanceID string, routeJSON string) error {
	req := &pb.Request{
		Payload: &pb.Request_AddRoute{
			AddRoute: &pb.AddRouteRequest{
				InstanceId: instanceID,
				RouteJson:  routeJSON,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if ar := resp.GetAddRoute(); ar != nil {
		if ar.Error != "" {
			return fmt.Errorf("add route: %s", ar.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// DeleteRoute removes a route from a server instance by route ID
func (c *Client) DeleteRoute(instanceID string, routeID string) error {
	req := &pb.Request{
		Payload: &pb.Request_DeleteRoute{
			DeleteRoute: &pb.DeleteRouteRequest{
				InstanceId: instanceID,
				RouteId:    routeID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if dr := resp.GetDeleteRoute(); dr != nil {
		if dr.Error != "" {
			return fmt.Errorf("delete route: %s", dr.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// AddUser adds or updates a user on a server instance
func (c *Client) AddUser(instanceID string, userJSON string) error {
	req := &pb.Request{
		Payload: &pb.Request_AddUser{
			AddUser: &pb.AddUserRequest{
				InstanceId: instanceID,
				UserJson:   userJSON,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if au := resp.GetAddUser(); au != nil {
		if au.Error != "" {
			return fmt.Errorf("add user: %s", au.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// DeleteUser removes a user from a server instance by UUID
func (c *Client) DeleteUser(instanceID string, userUUID string) error {
	req := &pb.Request{
		Payload: &pb.Request_DeleteUser{
			DeleteUser: &pb.DeleteUserRequest{
				InstanceId: instanceID,
				UserUuid:   userUUID,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if du := resp.GetDeleteUser(); du != nil {
		if du.Error != "" {
			return fmt.Errorf("delete user: %s", du.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}

// UpdateMetadata updates instance metadata like name and autostart toggle
func (c *Client) UpdateMetadata(instanceID, name string, autostart bool) error {
	req := &pb.Request{
		Payload: &pb.Request_UpdateMetadata{
			UpdateMetadata: &pb.UpdateMetadataRequest{
				InstanceId: instanceID,
				Name:       name,
				Autostart:  autostart,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if um := resp.GetUpdateMetadata(); um != nil {
		if um.Error != "" {
			return fmt.Errorf("update metadata: %s", um.Error)
		}
		return nil
	}

	return fmt.Errorf("unexpected response type")
}
