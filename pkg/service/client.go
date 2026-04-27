package service

import (
	"fmt"
	"net"
	"sync"

	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// Client communicates with a Turnable service server over a custom protocol
type Client struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewClient connects to a remote Turnable service server
func NewClient(network, addr string, clientPrivB64, clientPubB64 string) (*Client, error) {
	nc, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	var kp *KeyPair
	if clientPrivB64 != "" || clientPubB64 != "" {
		var err error
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

	return &Client{conn: wrapped}, nil
}

// Close closes the client connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// sendRequest sends a proto request and blocks for response
func (c *Client) sendRequest(req *pb.Request) (*pb.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.conn, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	var resp pb.Response
	if err := readFramed(c.conn, &resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return &resp, nil
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
