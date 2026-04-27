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
	EventLog          EventKind = iota // server emitted a log record
	EventDisconnected                  // connection was lost or closed
)

// Event is emitted by the client read loop to signal logs or disconnects
type Event struct {
	Kind EventKind
	Log  *pb.LogRecord
	Err  error
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
func (c *Client) StartServer(config string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartServer{
			StartServer: &pb.StartServerRequest{
				Config: config,
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
func (c *Client) StartClient(config string, listenAddr string) (string, error) {
	req := &pb.Request{
		Payload: &pb.Request_StartClient{
			StartClient: &pb.StartClientRequest{
				Config:     config,
				ListenAddr: listenAddr,
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

// ListInstances requests the list of all instances
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
