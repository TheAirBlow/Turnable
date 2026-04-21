package platform

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	vkAPIEndpoint     = "https://api.vk.com/method"    // VK API endpoint
	vkLoginEndpoint   = "https://login.vk.com"         // VK login endpoint
	vkCallsEndpoint   = "https://calls.okcdn.ru/fb.do" // VK calls backend endpoint
	vkClientID        = "6287487"                      // VK OAuth client ID
	vkClientSecret    = "QbYic1K3lEV5kTGiqlq2"         // VK OAuth client secret
	vkAPIVersion      = "5.275"                        // VK API version used by this client
	vkCallsAppKey     = "CGMMEJLGDIHBABABA"            // VK calls application key
	vkCallsClientVer  = "1.1"                          // VK calls client version
	vkCaptchaRetries  = 5                              // Max number of captcha retry attempts
	vkVideoTrackSlots = 36                             // Maximum video track slots reported to VK
)

// VKHandler manages VK authorization, signaling, and peer state
type VKHandler struct {
	once   sync.Once
	mu     sync.RWMutex // protects all data fields except conn/seq/readerCancel
	connMu sync.Mutex   // protects conn, seq, readerCancel

	httpClient *http.Client
	profile    common.BrowserProfile

	callID              string
	joinURL             string
	username            string
	messagesAccessToken string
	anonymToken         string
	sessionKey          string
	endpoint            string

	turnUser  string
	turnPass  string
	turnAddr  string
	turnAddrs []string

	conn         *websocket.Conn
	seq          int
	readerCancel context.CancelFunc

	participantsByID  map[int64]*vkParticipant
	participantByPeer map[string]int64
	remoteMedia       RemoteMediaInfo
	videoTrackSlots   int

	subscribers    map[int]chan Event
	nextSubscriber int

	interactive bool
}

// vkParticipant stores one call participant tracked from VK signaling
type vkParticipant struct {
	ID         int64
	PeerID     string
	ExternalID string
	Name       string
}

// ID returns the unique ID of this handler
func (V *VKHandler) ID() string {
	return "vk.com"
}

// GetConfig returns the platform configuration
func (V *VKHandler) GetConfig() Config {
	return Config{
		CanReuseTURN:   true,
		CanMultiplex:   true,
		BandwidthRelay: 250 * 1024,
		BandwidthP2P:   0,
	}
}

// GetTURNInfo returns the latest TURN server credentials learned from VK signaling
func (V *VKHandler) GetTURNInfo() TURNInfo {
	V.ensureInit()
	V.mu.RLock()
	defer V.mu.RUnlock()
	return TURNInfo{
		Address:   V.turnAddr,
		Addresses: append([]string(nil), V.turnAddrs...),
		Username:  V.turnUser,
		Password:  V.turnPass,
	}
}

// GetPeers returns all currently known peers connected to the call
func (V *VKHandler) GetPeers() []PeerInfo {
	V.ensureInit()
	V.mu.RLock()
	defer V.mu.RUnlock()

	ids := make([]int64, 0, len(V.participantsByID))
	for id := range V.participantsByID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	peers := make([]PeerInfo, 0, len(ids))
	for _, id := range ids {
		participant := V.participantsByID[id]
		if participant == nil {
			continue
		}
		peers = append(peers, PeerInfo{
			ID:         strconv.FormatInt(participant.ID, 10),
			PeerID:     participant.PeerID,
			ExternalID: participant.ExternalID,
			Name:       participant.Name,
		})
	}
	return peers
}

// GetRemoteMedia returns the latest parsed remote media description from signaling
func (V *VKHandler) GetRemoteMedia() RemoteMediaInfo {
	V.ensureInit()
	V.mu.RLock()
	defer V.mu.RUnlock()
	return cloneRemoteMediaInfo(V.remoteMedia)
}

// GetUsersBySourceIDs resolves participant or peer IDs to names when the roster contains them
func (V *VKHandler) GetUsersBySourceIDs(sourceIDs []string) (map[string]string, error) {
	V.ensureInit()
	result := make(map[string]string, len(sourceIDs))

	V.mu.RLock()
	externalIDs := make(map[string]struct{})
	for _, sourceID := range sourceIDs {
		participant := V.lookupParticipant(sourceID)
		if participant == nil {
			continue
		}
		if participant.Name != "" {
			result[sourceID] = participant.Name
			continue
		}
		if participant.ExternalID != "" {
			externalIDs[participant.ExternalID] = struct{}{}
			result[sourceID] = participant.ExternalID
		}
	}
	accessToken := V.messagesAccessToken
	callID := V.callID
	V.mu.RUnlock()

	if len(externalIDs) == 0 || common.IsNullOrWhiteSpace(accessToken) {
		return result, nil
	}

	namesByExternalID, err := V.fetchParticipantNames(context.Background(), callID, accessToken, externalIDs)
	if err != nil {
		return result, err
	}

	V.mu.Lock()
	for _, participant := range V.participantsByID {
		if name := namesByExternalID[participant.ExternalID]; name != "" {
			participant.Name = name
		}
	}
	for _, sourceID := range sourceIDs {
		if participant := V.lookupParticipant(sourceID); participant != nil && participant.Name != "" {
			result[sourceID] = participant.Name
		}
	}
	V.mu.Unlock()

	return result, nil
}

// WatchEvents subscribes to signaling events emitted by the internal signaling loop
func (V *VKHandler) WatchEvents(ctx context.Context) <-chan Event {
	V.ensureInit()
	out := make(chan Event, 16)
	sub := make(chan Event, 16)

	V.mu.Lock()
	id := V.nextSubscriber
	V.nextSubscriber++
	V.subscribers[id] = sub
	turnPayload := map[string]string{
		"username": V.turnUser,
		"password": V.turnPass,
		"address":  V.turnAddr,
	}
	V.mu.Unlock()

	V.connMu.Lock()
	connected := V.conn != nil
	V.connMu.Unlock()

	if connected {
		out <- Event{Type: EventTurnAuthUpdated, Payload: turnPayload}
	}

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				V.mu.Lock()
				delete(V.subscribers, id)
				V.mu.Unlock()
				return
			case event := <-sub:
				select {
				case out <- event:
				case <-ctx.Done():
					V.mu.Lock()
					delete(V.subscribers, id)
					V.mu.Unlock()
					return
				}
			}
		}
	}()

	return out
}

// ensureInit lazily initializes handler internals exactly once
func (V *VKHandler) ensureInit() {
	V.once.Do(func() {
		V.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:           common.ResolverDialContext(),
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				MaxIdleConns:          32,
				MaxIdleConnsPerHost:   8,
				IdleConnTimeout:       90 * time.Second,
				DisableCompression:    false,
			},
		}

		proxyStr := os.Getenv("VK_PROXY")
		if !common.IsNullOrWhiteSpace(proxyStr) {
			proxyURL, _ := url.Parse(proxyStr)
			transport, _ := V.httpClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}

		V.profile = common.RandomBrowserProfile()
		slog.Debug("vk browser profile", "user_agent", V.profile.UserAgent, "sec_ch_ua", V.profile.SecChUa, "sec_ch_ua_platform", V.profile.SecChUaPlatform, "sec_ch_ua_mobile", V.profile.SecChUaMobile)

		V.participantsByID = make(map[int64]*vkParticipant)
		V.participantByPeer = make(map[string]int64)
		V.subscribers = make(map[int]chan Event)
		V.videoTrackSlots = vkVideoTrackSlots
	})
}

// ensureParticipant returns the participant entry for the given ID, creating it if needed; mu must be held
func (V *VKHandler) ensureParticipant(participantID int64) *vkParticipant {
	if participant := V.participantsByID[participantID]; participant != nil {
		return participant
	}
	participant := &vkParticipant{ID: participantID}
	V.participantsByID[participantID] = participant
	return participant
}

// lookupParticipant resolves a peer or participant ID to a participant entry; mu must be held
func (V *VKHandler) lookupParticipant(sourceID string) *vkParticipant {
	if sourceID == "" {
		return nil
	}
	if participantID, ok := V.participantByPeer[sourceID]; ok {
		return V.participantsByID[participantID]
	}
	if parsed, err := strconv.ParseInt(sourceID, 10, 64); err == nil {
		return V.participantsByID[parsed]
	}
	return nil
}
