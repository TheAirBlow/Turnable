package platform

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

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
	mu sync.Mutex

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

	conn *websocket.Conn
	seq  int

	readerCancel context.CancelFunc

	participantsByID  map[int64]*vkParticipant
	participantByPeer map[string]int64
	remoteMedia       RemoteMediaInfo
	videoTrackSlots   int

	subscribers    map[int]chan Event
	nextSubscriber int
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
		CanReuseTURN: true,
		CanMultiplex: true,
	}
}

// GetTURNInfo returns the latest TURN server credentials learned from VK signaling
func (V *VKHandler) GetTURNInfo() TURNInfo {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	return TURNInfo{
		Address:   V.turnAddr,
		Addresses: append([]string(nil), V.turnAddrs...),
		Username:  V.turnUser,
		Password:  V.turnPass,
	}
}

// GetPeers returns all currently known peers connected to the call
func (V *VKHandler) GetPeers() []PeerInfo {
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()

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
	V.mu.Lock()
	defer V.mu.Unlock()

	V.ensureInitLocked()
	return cloneRemoteMediaInfo(V.remoteMedia)
}

// GetUsersBySourceIDs resolves participant or peer IDs to names when the roster contains them
func (V *VKHandler) GetUsersBySourceIDs(sourceIDs []string) (map[string]string, error) {
	result := make(map[string]string, len(sourceIDs))

	V.mu.Lock()
	V.ensureInitLocked()
	externalIDs := make(map[string]struct{})
	for _, sourceID := range sourceIDs {
		participant := V.lookupParticipantLocked(sourceID)
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
	V.mu.Unlock()

	if len(externalIDs) == 0 || common.IsNullOrWhiteSpace(accessToken) {
		return result, nil
	}

	namesByExternalID, err := V.fetchParticipantNames(context.Background(), callID, accessToken, externalIDs)
	if err != nil {
		return result, err
	}

	V.mu.Lock()
	defer V.mu.Unlock()
	V.ensureInitLocked()

	for _, participant := range V.participantsByID {
		if name := namesByExternalID[participant.ExternalID]; name != "" {
			participant.Name = name
		}
	}

	for _, sourceID := range sourceIDs {
		if participant := V.lookupParticipantLocked(sourceID); participant != nil && participant.Name != "" {
			result[sourceID] = participant.Name
		}
	}

	return result, nil
}

// WatchEvents subscribes to signaling events emitted by the internal signaling loop
func (V *VKHandler) WatchEvents(ctx context.Context) <-chan Event {
	out := make(chan Event, 16)
	sub := make(chan Event, 16)
	V.mu.Lock()
	V.ensureInitLocked()
	id := V.nextSubscriber
	V.nextSubscriber++
	V.subscribers[id] = sub
	turnPayload := map[string]string{
		"username": V.turnUser,
		"password": V.turnPass,
		"address":  V.turnAddr,
	}
	connected := V.conn != nil
	V.mu.Unlock()

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

// ensureInitLocked lazily initializes handler internals while the mutex is held
func (V *VKHandler) ensureInitLocked() {
	if V.httpClient != nil {
		return
	}
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	//proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	V.httpClient = &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			//Proxy:               http.ProxyURL(proxyURL),
			//TLSClientConfig: &tls.Config{
			//	InsecureSkipVerify: true,
			//},
		},
	}
	V.profile = common.RandomBrowserProfile()
	slog.Debug("vk browser profile", "user_agent", V.profile.UserAgent, "sec_ch_ua", V.profile.SecChUa, "sec_ch_ua_platform", V.profile.SecChUaPlatform, "sec_ch_ua_mobile", V.profile.SecChUaMobile)
	V.participantsByID = make(map[int64]*vkParticipant)
	V.participantByPeer = make(map[string]int64)
	V.subscribers = make(map[int]chan Event)
	V.videoTrackSlots = vkVideoTrackSlots
}

// ensureParticipantLocked returns the participant entry for the given ID, creating it if needed
func (V *VKHandler) ensureParticipantLocked(participantID int64) *vkParticipant {
	if participant := V.participantsByID[participantID]; participant != nil {
		return participant
	}
	participant := &vkParticipant{ID: participantID}
	V.participantsByID[participantID] = participant
	return participant
}

// lookupParticipantLocked resolves a peer or participant ID to a participant entry
func (V *VKHandler) lookupParticipantLocked(sourceID string) *vkParticipant {
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
