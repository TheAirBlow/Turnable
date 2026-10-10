package service

import (
	"fmt"

	"github.com/theairblow/turnable/pkg/engine"
	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// serverInstance fetches a running server instance by ID
func (s *Server) serverInstance(id string) (*Instance, error) {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("instance %q not found", id)
	}

	if inst.server == nil {
		return nil, fmt.Errorf("instance %q is not a server", id)
	}

	if !inst.server.IsRunning() {
		return nil, fmt.Errorf("instance %q is not running", id)
	}

	return inst, nil
}

// getStats returns stats of a server instance, resetting the usage counters if asked to
func (s *Server) getStats(req *pb.GetStatsRequest) *pb.GetStatsResponse {
	inst, err := s.serverInstance(req.InstanceId)
	if err != nil {
		return &pb.GetStatsResponse{Error: err.Error()}
	}

	st := inst.server.Stats()
	resp := &pb.GetStatsResponse{
		Totals: &pb.ServerTotals{
			Started:  st.Started.Unix(),
			Usage:    usageToProto(st.Usage),
			Channels: int32(st.Channels),
			Sessions: int32(st.Sessions),
			Users:    int32(st.Users),
		},
	}

	for _, u := range inst.server.Users() {
		var lastSeen int64
		if !u.LastSeen.IsZero() {
			lastSeen = u.LastSeen.Unix()
		}

		resp.Users = append(resp.Users, &pb.UserStats{
			Uuid:     u.UUID,
			Usage:    usageToProto(u.Usage),
			Channels: int32(u.Channels),
			Sessions: int32(u.Sessions),
			Ips:      u.IPs,
			Online:   u.Online,
			LastSeen: lastSeen,
		})
	}

	if req.Collect {
		resp.Collected = map[string]*pb.Usage{}
		for uuid, u := range inst.server.CollectUsage() {
			resp.Collected[uuid] = usageToProto(u)
		}
	}

	return resp
}

// listSessions returns the live sessions of a server instance
func (s *Server) listSessions(id string) *pb.ListSessionsResponse {
	inst, err := s.serverInstance(id)
	if err != nil {
		return &pb.ListSessionsResponse{Error: err.Error()}
	}

	resp := &pb.ListSessionsResponse{}
	for _, ss := range inst.server.Sessions() {
		resp.Sessions = append(resp.Sessions, &pb.SessionStats{
			Id:       ss.ID,
			UserUuid: ss.User,
			RouteId:  ss.Route,
			Addr:     ss.Addr,
			Since:    ss.Since.Unix(),
			Usage:    usageToProto(ss.Usage),
			Channels: int32(ss.Channels),
		})
	}

	return resp
}

// kick closes the tunnels of a user or a session on a server instance
func (s *Server) kick(req *pb.KickRequest) *pb.KickResponse {
	inst, err := s.serverInstance(req.InstanceId)
	if err != nil {
		return &pb.KickResponse{Error: err.Error()}
	}

	switch {
	case req.UserUuid != "" && req.SessionId == "":
		return &pb.KickResponse{Kicked: int32(inst.server.KickUser(req.UserUuid))}
	case req.SessionId != "" && req.UserUuid == "":
		return &pb.KickResponse{Kicked: int32(inst.server.KickSession(req.SessionId))}
	}

	return &pb.KickResponse{Error: "set exactly one of user_uuid and session_id"}
}

// kickProviderUser closes the tunnels of a user on every running server instance using the provider
func (s *Server) kickProviderUser(providerUUID, userUUID string) {
	s.mu.RLock()
	var servers []*engine.TurnableServer
	for _, inst := range s.instances {
		if inst.server != nil && inst.ProviderUUID == providerUUID {
			servers = append(servers, inst.server)
		}
	}
	s.mu.RUnlock()

	for _, srv := range servers {
		if n := srv.KickUser(userUUID); n > 0 {
			s.log.Info("closed tunnels of a deleted user", "provider", providerUUID, "user", userUUID, "tunnels", n)
		}
	}
}

// forwardSessionEvents broadcasts the tunnel events of a server instance until it stops
func (s *Server) forwardSessionEvents(inst *Instance) {
	events, cancel := inst.server.Subscribe(256)
	inst.setUnsubscribe(cancel)

	for ev := range events {
		out := &pb.SessionEvent{
			InstanceId: inst.ID,
			UserUuid:   ev.User,
			SessionId:  ev.Session,
			RouteId:    ev.Route,
			Addr:       ev.Addr,
			Time:       ev.At.Unix(),
			Usage:      usageToProto(ev.Usage),
			Online:     int32(ev.Online),
		}

		if ev.Type == engine.EventConnect {
			out.EventType = pb.SessionEventType_SESSION_EVENT_TYPE_CONNECT
		} else {
			out.EventType = pb.SessionEventType_SESSION_EVENT_TYPE_DISCONNECT
		}

		s.broadcastSessionEvent(out)
	}
}

// broadcastSessionEvent sends a SessionEvent to all connected service clients
func (s *Server) broadcastSessionEvent(event *pb.SessionEvent) {
	s.relay.broadcast.mu.RLock()
	defer s.relay.broadcast.mu.RUnlock()
	for c := range s.relay.broadcast.subs {
		select {
		case c.writeCh <- &pb.Response{Payload: &pb.Response_SessionEvent{SessionEvent: event}}:
		case <-c.done:
		default:
			// slow clients miss session events, they can poll the stats instead
		}
	}
}

// usageToProto converts engine usage to its protobuf form
func usageToProto(u engine.Usage) *pb.Usage {
	return &pb.Usage{Up: u.Up, Down: u.Down}
}
