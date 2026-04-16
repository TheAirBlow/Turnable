package platform

import (
	"context"

	"github.com/theairblow/turnable/pkg/common"
)

// TODO: GetConfig is not respected in any way yet...

// Handler represents a platform handler
type Handler interface {
	ID() string                                                        // Returns the unique ID of this handler
	GetConfig() Config                                                 // Returns the platform configuration
	GetTURNInfo() TURNInfo                                             // Returns the latest TURN server credentials
	Authorize(callID string, username string) error                    // Authorizes with the platform's servers
	Connect() error                                                    // Connects to the signaling server
	Disconnect() error                                                 // Gracefully disconnects from the signaling server
	Close() error                                                      // Forcibly closes the current signaling connection
	NotifyVideoStream(active bool) error                               // Notifies the signaling server that a video stream was started
	GetPeers() []PeerInfo                                              // Returns all currently known peers connected to the call
	GetRemoteMedia() RemoteMediaInfo                                   // Returns the latest parsed remote media description from signaling
	GetUsersBySourceIDs(sourceIDs []string) (map[string]string, error) // Resolves peer or participant IDs to user IDs when available
	WatchEvents(ctx context.Context) <-chan Event                      // Emits signaling events
}

// Config represents platform configuration
type Config struct {
	CanReuseTURN bool // Whether the client can reuse the same TURN credentials to make multiple connections
	CanMultiplex bool // Whether the client/server can request multiple anonymous identities from the same IP
}

// TURNInfo describes the TURN server credentials currently advertised by signaling.
type TURNInfo struct {
	Address   string
	Addresses []string
	Username  string
	Password  string
}

// PeerInfo represents a currently known participant/peer snapshot.
type PeerInfo struct {
	ID         string // Platform-local participant identifier.
	PeerID     string // Platform-specific transport/signaling peer identifier.
	ExternalID string // External user identifier exposed by the platform.
	Name       string // Resolved display name, when available.
}

// MediaKind represents the generic kind of remote media section.
type MediaKind string

const (
	MediaKindUnknown     MediaKind = "unknown"     // Media section kind is unknown.
	MediaKindAudio       MediaKind = "audio"       // RTP audio media section.
	MediaKindVideo       MediaKind = "video"       // RTP video media section.
	MediaKindApplication MediaKind = "application" // Non-RTP application/data media section.
)

// MediaDirection represents the direction advertised for a remote media section.
type MediaDirection string

const (
	MediaDirectionUnknown  MediaDirection = "unknown"  // Media direction is unknown.
	MediaDirectionSendOnly MediaDirection = "sendonly" // Remote side sends on this section.
	MediaDirectionRecvOnly MediaDirection = "recvonly" // Remote side receives on this section.
	MediaDirectionSendRecv MediaDirection = "sendrecv" // Both sides may send and receive.
	MediaDirectionInactive MediaDirection = "inactive" // Media section is inactive.
)

// RemoteMediaTrack describes one remote media section from the latest offer.
type RemoteMediaTrack struct {
	Index     int            // Zero-based media section index in SDP order
	MID       string         // MID of the media section
	Kind      MediaKind      // Media kind (audio, video, application)
	Direction MediaDirection // Offered direction of the media section
	StreamID  string         // Stream identifier from msid, when present
	TrackID   string         // Track identifier from msid, when present
	SourceIDs []string       // SSRC-like source identifiers exposed by signaling
}

// RemoteMediaInfo describes the latest remote media topology exposed by signaling.
type RemoteMediaInfo struct {
	BundleMIDs             []string           // Media section order advertised in the BUNDLE group
	Tracks                 []RemoteMediaTrack // Parsed media sections in the same order as the offer
	OfferedVideoTrackSlots int                // Count of remote sendonly video slots in the current offer
}

// EventType represents a signaling event
type EventType int

const (
	EventRemoteMediaUpdated  EventType = iota // Remote media description was updated
	EventParticipantsChanged                  // Someone joined or left
	EventTurnAuthUpdated                      // New TURN credentials available
	EventCallEnded                            // The session is closed
)

// Event represents a signaling event with arbitrary data
type Event struct {
	Type     EventType
	Payload  any
	Metadata map[string]string
}

// Handlers represents platform Handler registry
var Handlers = common.NewRegistry[Handler]()

// init registers all available platform handlers
func init() {
	common.PlatformsHolder = Handlers
	Handlers.Register(&VKHandler{})
}

// GetHandler fetches a platform Handler by its string ID
func GetHandler(name string) (Handler, error) {
	return Handlers.Get(name)
}

// ListHandlers lists all platform Handler string IDs
func ListHandlers() []string {
	return Handlers.List()
}

// HandlerExists checks whether a platform Handler with specified string ID exists
func HandlerExists(name string) bool {
	return Handlers.Exists(name)
}
