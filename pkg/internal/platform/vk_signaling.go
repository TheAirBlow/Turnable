package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/sdp/v3"

	"github.com/theairblow/turnable/pkg/common"
)

// vkMessage stores one decoded VK signaling message
type vkMessage struct {
	Type               string         `json:"type"`
	Notification       string         `json:"notification"`
	Response           string         `json:"response"`
	Sequence           int            `json:"sequence"`
	Description        string         `json:"description"`
	ParticipantID      float64        `json:"participantId"`
	Participant        map[string]any `json:"participant"`
	PeerID             map[string]any `json:"peerId"`
	Reason             string         `json:"reason"`
	Endpoint           string         `json:"endpoint"`
	Conversation       map[string]any `json:"conversation"`
	ConversationParams map[string]any `json:"conversationParams"`
}

// Connect connects to the signaling server and starts the internal signaling loop
func (V *VKHandler) Connect() error {
	V.mu.Lock()
	V.ensureInitLocked()
	if common.IsNullOrWhiteSpace(V.endpoint) {
		V.mu.Unlock()
		slog.Warn("vk signaling connect rejected: not authorized")
		return errors.New("authorize must be called before connect")
	}
	if V.conn != nil {
		V.mu.Unlock()
		return nil
	}

	header := http.Header{}
	header.Set("Origin", "https://vk.com")
	header.Set("User-Agent", V.profile.UserAgent)

	// Chromium websocket captures show these query params are always present and appear to
	// influence backend behavior/validation.
	endpoint := V.endpoint
	if parsed, err := url.Parse(endpoint); err == nil {
		q := parsed.Query()
		q.Set("platform", "WEB")
		q.Set("appVersion", "1.1")
		q.Set("version", "5")
		q.Set("device", "browser")
		q.Set("capabilities", "2F7F")
		q.Set("clientType", "VK")
		q.Set("tgt", "retry")
		parsed.RawQuery = q.Encode()
		endpoint = parsed.String()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, endpoint, header)
	if err != nil {
		V.mu.Unlock()
		slog.Warn("vk signaling websocket dial failed", "error", err)
		return err
	}

	V.conn = conn
	V.seq = 1

	if err := V.writeCommandLocked("allocate-consumer", map[string]any{
		"capabilities": map[string]any{
			"estimatedPerformanceIndex":              0,
			"audioMix":                               true,
			"consumerUpdate":                         true,
			"producerNotificationDataChannelVersion": 8,
			"producerCommandDataChannelVersion":      3,
			"consumerScreenDataChannelVersion":       1,
			"producerScreenDataChannelVersion":       1,
			"asrDataChannelVersion":                  1,
			"animojiDataChannelVersion":              2,
			"animojiBackendRender":                   true,
			"onDemandTracks":                         true,
			"unifiedPlan":                            true,
			"singleSession":                          true,
			"videoTracksCount":                       V.videoTrackSlots,
			"red":                                    true,
			"audioShare":                             false,
			"fastScreenShare":                        true,
			"videoSuspend":                           true,
			"simulcast":                              false,
			"consumerFastScreenShare":                false,
			"consumerFastScreenShareQualityOnDemand": false,
		},
	}); err != nil {
		_ = conn.Close()
		V.conn = nil
		V.mu.Unlock()
		slog.Warn("vk signaling setup command failed", "command", "allocate-consumer", "error", err)
		return err
	}

	if err := V.writeCommandLocked("change-media-settings", map[string]any{
		"mediaSettings": map[string]bool{
			"isAudioEnabled":             false,
			"isVideoEnabled":             false,
			"isScreenSharingEnabled":     false,
			"isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled":      false,
			"isAnimojiEnabled":           false,
		},
	}); err != nil {
		_ = conn.Close()
		V.conn = nil
		V.mu.Unlock()
		slog.Warn("vk signaling setup command failed", "command", "change-media-settings", "error", err)
		return err
	}

	if err := V.writeCommandLocked("update-media-modifiers", map[string]any{
		"mediaModifiers": map[string]bool{
			"denoise":    true,
			"denoiseAnn": true,
		},
	}); err != nil {
		_ = conn.Close()
		V.conn = nil
		V.mu.Unlock()
		slog.Warn("vk signaling setup command failed", "command", "update-media-modifiers", "error", err)
		return err
	}

	readerCtx, readerCancel := context.WithCancel(context.Background())
	V.readerCancel = readerCancel
	turnPayload := map[string]string{
		"username": V.turnUser,
		"password": V.turnPass,
		"address":  V.turnAddr,
	}
	endpointHost := ""
	if parsedEndpoint, parseErr := url.Parse(endpoint); parseErr == nil {
		endpointHost = parsedEndpoint.Host
	}
	conn = V.conn
	V.mu.Unlock()

	go V.runSignalingLoop(readerCtx, conn)
	V.broadcast(Event{Type: EventTurnAuthUpdated, Payload: turnPayload})
	slog.Info(
		"vk signaling connected",
		"endpoint_host",
		endpointHost,
	)
	return nil
}

// Disconnect gracefully disconnects from the signaling server
func (V *VKHandler) Disconnect() error {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	if V.conn == nil {
		return nil
	}

	if err := V.writeCommandLocked("hangup", map[string]any{"reason": "HUNGUP"}); err != nil {
		if V.readerCancel != nil {
			V.readerCancel()
			V.readerCancel = nil
		}
		_ = V.conn.Close()
		V.conn = nil
		slog.Warn("vk signaling disconnect hangup failed", "error", err)
		return err
	}

	err := V.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second),
	)
	if V.readerCancel != nil {
		V.readerCancel()
		V.readerCancel = nil
	}
	closeErr := V.conn.Close()
	V.conn = nil

	if err != nil {
		slog.Warn("vk signaling disconnect close control failed", "error", err)
		return err
	}
	if closeErr != nil {
		if !errors.Is(closeErr, net.ErrClosed) && !strings.Contains(strings.ToLower(closeErr.Error()), "use of closed network connection") {
			slog.Warn("vk signaling disconnect close failed", "error", closeErr)
			return closeErr
		}
		slog.Debug("vk signaling disconnect close: already closed")
	}
	return nil
}

// Close forcibly closes the current signaling connection
func (V *VKHandler) Close() error {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	if V.conn == nil {
		return nil
	}
	slog.Info("vk signaling force close")
	if V.readerCancel != nil {
		V.readerCancel()
		V.readerCancel = nil
	}
	err := V.conn.Close()
	V.conn = nil
	if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") {
		slog.Warn("vk signaling force close failed", "error", err)
		return err
	}
	return nil
}

// NotifyVideoStream notifies the signaling server that screen sharing was started or stopped
func (V *VKHandler) NotifyVideoStream(active bool) error {
	return V.writeSimpleCommand("change-media-settings", map[string]any{
		"mediaSettings": map[string]bool{
			"isAudioEnabled":             false,
			"isVideoEnabled":             false,
			"isScreenSharingEnabled":     active,
			"isFastScreenSharingEnabled": active,
			"isAudioSharingEnabled":      false,
			"isAnimojiEnabled":           false,
		},
	})
}

// handleIncomingMessage updates local state and converts a signaling message into events
func (V *VKHandler) handleIncomingMessage(msg *vkMessage) []Event {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	switch msg.Notification {
	case "connection":
		if msg.Endpoint != "" {
			V.endpoint = msg.Endpoint
		}
		if turnRaw, ok := msg.ConversationParams["turn"]; ok {
			if turn, ok := turnRaw.(map[string]any); ok {
				V.turnUser = common.StringifyAny(turn["username"])
				V.turnPass = common.FirstNonEmpty(common.StringifyAny(turn["credential"]), common.StringifyAny(turn["password"]))
				if urls, ok := turn["urls"].([]any); ok {
					raw := make([]string, 0, len(urls))
					for _, u := range urls {
						raw = append(raw, common.StringifyAny(u))
					}
					addresses := normalizeTurnAddresses(raw)
					if len(addresses) > 0 {
						V.turnAddr = addresses[0]
						V.turnAddrs = addresses
					}
				}
			}
		}
		return V.handleConnectionSnapshotLocked(msg.Conversation)
	case "producer-updated":
		remoteMedia, err := parseRemoteMediaDescription(msg.Description)
		if err != nil {
			slog.Warn("vk signaling producer update parse failed", "error", err)
			return []Event{{
				Type:     EventCallEnded,
				Metadata: map[string]string{"error": "invalid producer offer: " + err.Error()},
			}}
		}
		V.remoteMedia = remoteMedia
		// TODO: send accept-producer response with SDP answer
		return []Event{{Type: EventRemoteMediaUpdated, Payload: cloneRemoteMediaInfo(remoteMedia)}}
	case "participant-joined":
		participantID := int64(msg.ParticipantID)
		participant := V.ensureParticipantLocked(participantID)
		participant.ID = participantID
		if participantMap := msg.Participant; participantMap != nil {
			if externalID, ok := common.NestedString(participantMap, "externalId", "id"); ok {
				participant.ExternalID = externalID
			}
			if peerID, ok := common.NestedString(participantMap, "peerId", "id"); ok {
				participant.PeerID = peerID
				V.participantByPeer[peerID] = participantID
			}
		}
		return []Event{{
			Type:    EventParticipantsChanged,
			Payload: map[string]string{"participant_id": strconv.FormatInt(participantID, 10), "external_id": participant.ExternalID},
		}}
	case "registered-peer":
		participantID := int64(msg.ParticipantID)
		participant := V.ensureParticipantLocked(participantID)
		if msg.PeerID != nil {
			peerID := common.StringifyAny(msg.PeerID["id"])
			if peerID != "" {
				participant.PeerID = peerID
				V.participantByPeer[peerID] = participantID
			}
		}
	case "hungup", "closed-conversation":
		return []Event{{Type: EventCallEnded, Metadata: map[string]string{"reason": common.FirstNonEmpty(msg.Reason, msg.Notification)}}}
	}
	return nil
}

// handleConnectionSnapshotLocked registers participants from the initial connection snapshot
func (V *VKHandler) handleConnectionSnapshotLocked(conversation map[string]any) []Event {
	participantsRaw, ok := conversation["participants"].([]any)
	if !ok || len(participantsRaw) == 0 {
		return nil
	}

	events := make([]Event, 0, len(participantsRaw))
	for _, raw := range participantsRaw {
		participantMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		participantID := int64(0)
		switch typed := participantMap["id"].(type) {
		case float64:
			participantID = int64(typed)
		case int64:
			participantID = typed
		case string:
			parsed, err := strconv.ParseInt(typed, 10, 64)
			if err != nil {
				continue
			}
			participantID = parsed
		default:
			continue
		}
		if participantID == 0 {
			continue
		}

		participant := V.ensureParticipantLocked(participantID)
		participant.ID = participantID
		if externalID, ok := common.NestedString(participantMap, "externalId", "id"); ok {
			participant.ExternalID = externalID
		}
		if peerID, ok := common.NestedString(participantMap, "peerId", "id"); ok {
			participant.PeerID = peerID
			V.participantByPeer[peerID] = participantID
		}

		events = append(events, Event{
			Type:    EventParticipantsChanged,
			Payload: map[string]string{"participant_id": strconv.FormatInt(participantID, 10), "external_id": participant.ExternalID},
		})
	}
	return events
}

// runSignalingLoop owns websocket reads and periodic pings for the active connection
func (V *VKHandler) runSignalingLoop(ctx context.Context, conn *websocket.Conn) {
	const pingInterval = 5 * time.Second

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	type readResult struct {
		messageType int
		payload     []byte
		err         error
	}
	readCh := make(chan readResult, 1)
	go func() {
		for {
			messageType, payload, err := conn.ReadMessage()
			readCh <- readResult{messageType: messageType, payload: payload, err: err}
			if err != nil {
				return
			}
		}
	}()

	terminate := func(err error) {
		V.mu.Lock()
		if V.conn == conn {
			V.conn = nil
			V.readerCancel = nil
		}
		V.mu.Unlock()
		V.broadcast(Event{Type: EventCallEnded, Metadata: map[string]string{"error": err.Error()}})
		slog.Warn("vk signaling loop terminated", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return
		case <-pingTicker.C:
			V.mu.Lock()
			if V.conn == conn {
				if err := conn.WriteControl(
					websocket.PingMessage,
					nil,
					time.Now().Add(2*time.Second),
				); err != nil {
					V.mu.Unlock()
					terminate(err)
					return
				}
			}
			V.mu.Unlock()
		case result := <-readCh:
			if result.err != nil {
				terminate(result.err)
				return
			}
			if result.messageType != websocket.TextMessage {
				continue
			}
			if string(result.payload) == "pong" || string(result.payload) == "ping" {
				continue
			}

			var msg vkMessage
			if err := json.Unmarshal(result.payload, &msg); err != nil {
				slog.Debug("vk signaling payload decode failed", "error", err)
				continue
			}

			if msg.Notification == "" && msg.Response == "" && msg.Type == "" {
				slog.Debug(
					"vk signaling unclassified payload",
					"bytes",
					len(result.payload),
					"preview",
					compactPayloadPreview(result.payload, 180),
				)
				continue
			}
			if strings.EqualFold(msg.Type, "error") {
				slog.Warn(
					"vk signaling error message",
					"bytes", len(result.payload),
					"response", msg.Response,
				)
				continue
			}
			slog.Debug(
				"vk signaling inbound message",
				"bytes", len(result.payload),
				"type", msg.Type,
				"notification", msg.Notification,
				"response", msg.Response,
				"sequence", msg.Sequence,
			)
			for _, event := range V.handleIncomingMessage(&msg) {
				V.broadcast(event)
			}
		}
	}
}

// broadcast fan-outs an event to all active subscribers without blocking
func (V *VKHandler) broadcast(event Event) {
	V.mu.Lock()
	V.ensureInitLocked()
	subscribers := make([]chan Event, 0, len(V.subscribers))
	for _, ch := range V.subscribers {
		subscribers = append(subscribers, ch)
	}
	V.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// writeSimpleCommand sends a signaling command while holding the handler lock
func (V *VKHandler) writeSimpleCommand(command string, payload map[string]any) error {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	if V.conn == nil {
		return errors.New("signaling connection is not established")
	}
	return V.writeCommandLocked(command, payload)
}

// writeCommandLocked serializes and writes a signaling command while the mutex is held
func (V *VKHandler) writeCommandLocked(command string, payload map[string]any) error {
	V.ensureInitLocked()
	sequence := V.seq
	V.seq++
	encoded, err := marshalCommandJSON(command, sequence, payload)
	if err != nil {
		return err
	}
	slog.Debug("vk signaling command write", "command", command, "sequence", sequence)
	if err := V.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := V.conn.WriteMessage(websocket.TextMessage, encoded); err != nil {
		return err
	}
	return V.conn.SetWriteDeadline(time.Time{})
}

// compactPayloadPreview truncates a payload string for debug logging
func compactPayloadPreview(payload []byte, max int) string {
	text := strings.TrimSpace(string(payload))
	if max <= 0 || len(text) <= max {
		return text
	}
	return fmt.Sprintf("%s...", text[:max])
}

// marshalCommandJSON builds a stable JSON frame for a VK signaling command
func marshalCommandJSON(command string, sequence int, payload map[string]any) ([]byte, error) {
	var out bytes.Buffer
	cmdJSON, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	out.WriteByte('{')
	out.WriteString(`"command":`)
	out.Write(cmdJSON)
	out.WriteString(`,"sequence":`)
	out.WriteString(strconv.Itoa(sequence))

	keys := make([]string, 0, len(payload))
	for key := range payload {
		if key == "command" || key == "sequence" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := json.Marshal(payload[key])
		if err != nil {
			return nil, err
		}
		out.WriteByte(',')
		out.Write(keyJSON)
		out.WriteByte(':')
		out.Write(valueJSON)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// cloneRemoteMediaInfo copies the parsed remote media snapshot for safe external use
func cloneRemoteMediaInfo(info RemoteMediaInfo) RemoteMediaInfo {
	cloned := RemoteMediaInfo{
		BundleMIDs:             append([]string(nil), info.BundleMIDs...),
		OfferedVideoTrackSlots: info.OfferedVideoTrackSlots,
		Tracks:                 make([]RemoteMediaTrack, 0, len(info.Tracks)),
	}
	for _, track := range info.Tracks {
		cloned.Tracks = append(cloned.Tracks, RemoteMediaTrack{
			Index:     track.Index,
			MID:       track.MID,
			Kind:      track.Kind,
			Direction: track.Direction,
			StreamID:  track.StreamID,
			TrackID:   track.TrackID,
			SourceIDs: append([]string(nil), track.SourceIDs...),
		})
	}
	return cloned
}

// parseRemoteMediaDescription parses the remote media description from VK signaling
func parseRemoteMediaDescription(raw string) (RemoteMediaInfo, error) {
	var session sdp.SessionDescription
	if err := session.Unmarshal([]byte(raw)); err != nil {
		return RemoteMediaInfo{}, err
	}

	bundleMIDs := []string(nil)
	for _, attr := range session.Attributes {
		if attr.Key != "group" {
			continue
		}
		parts := strings.Fields(attr.Value)
		if len(parts) > 1 && parts[0] == "BUNDLE" {
			bundleMIDs = append([]string(nil), parts[1:]...)
			break
		}
	}

	info := RemoteMediaInfo{
		BundleMIDs: bundleMIDs,
		Tracks:     make([]RemoteMediaTrack, 0, len(session.MediaDescriptions)),
	}
	for index, media := range session.MediaDescriptions {
		mid := ""
		msid := ""
		direction := MediaDirectionSendRecv
		sourceIDs := make([]string, 0, 2)
		seenSSRC := make(map[string]struct{})

		for _, attr := range media.Attributes {
			switch attr.Key {
			case "mid":
				if mid == "" {
					mid = attr.Value
				}
			case "msid":
				if msid == "" {
					msid = attr.Value
				}
			case "sendonly":
				direction = MediaDirectionSendOnly
			case "recvonly":
				direction = MediaDirectionRecvOnly
			case "sendrecv":
				direction = MediaDirectionSendRecv
			case "inactive":
				direction = MediaDirectionInactive
			case "ssrc":
				ssrc := strings.TrimSpace(strings.SplitN(attr.Value, " ", 2)[0])
				if ssrc == "" {
					continue
				}
				if _, ok := seenSSRC[ssrc]; ok {
					continue
				}
				seenSSRC[ssrc] = struct{}{}
				sourceIDs = append(sourceIDs, ssrc)
			}
		}

		kind := MediaKindUnknown
		switch strings.ToLower(media.MediaName.Media) {
		case "audio":
			kind = MediaKindAudio
		case "video":
			kind = MediaKindVideo
		case "application":
			kind = MediaKindApplication
		}

		streamID := ""
		trackID := ""
		msidParts := strings.Fields(msid)
		if len(msidParts) > 0 {
			streamID = msidParts[0]
		}
		if len(msidParts) > 1 {
			trackID = msidParts[1]
		}

		track := RemoteMediaTrack{
			Index:     index,
			MID:       mid,
			Kind:      kind,
			Direction: direction,
			StreamID:  streamID,
			TrackID:   trackID,
			SourceIDs: sourceIDs,
		}
		if track.Kind == MediaKindVideo && track.Direction == MediaDirectionSendOnly {
			info.OfferedVideoTrackSlots++
		}
		info.Tracks = append(info.Tracks, track)
	}
	return info, nil
}
