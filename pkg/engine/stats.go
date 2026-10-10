package engine

import (
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Usage represents traffic in bytes from the server's point of view
type Usage struct {
	Up   int64 // sent by clients into the tunnel
	Down int64 // sent back to clients
}

// UserStats represents what the server knows about a user
type UserStats struct {
	UUID     string    // User UUID
	Usage    Usage     // Traffic since the server started
	Channels int       // Live tunnels
	Sessions int       // Live sessions
	IPs      []string  // Addresses the user is connected from
	Online   bool      // Whether the user has a live tunnel
	LastSeen time.Time // Last time a tunnel opened or closed
}

// SessionInfo represents a live session
type SessionInfo struct {
	ID       string    // Session UUID
	User     string    // User UUID
	Route    string    // Route ID
	Addr     string    // Client address
	Since    time.Time // When the session started
	Usage    Usage     // Traffic of all its tunnels
	Channels int       // Live tunnels
}

// ServerStats represents server wide numbers
type ServerStats struct {
	Started  time.Time // When the server started
	Usage    Usage     // Total traffic
	Channels int       // Live tunnels
	Sessions int       // Live sessions
	Users    int       // Users with a live tunnel
}

// EventType represents what happened to a tunnel
type EventType string

const (
	EventConnect    EventType = "connect"    // a tunnel opened
	EventDisconnect EventType = "disconnect" // a tunnel closed
)

// Event represents a tunnel opening or closing
type Event struct {
	Type    EventType // What happened
	User    string    // User UUID
	Session string    // Session UUID
	Route   string    // Route ID
	Addr    string    // Client address
	At      time.Time // When it happened
	Usage   Usage     // Traffic of the tunnel, set on disconnect
	Online  int       // Live tunnels of the user afterwards
}

// tracker counts traffic and keeps track of live tunnels
type tracker struct {
	started time.Time    // when the server started
	up      atomic.Int64 // total upload
	down    atomic.Int64 // total download

	mu       sync.Mutex
	users    map[string]*userRec
	sessions map[string]*sessionRec
	subs     map[chan Event]struct{}
}

// userRec is the books of a single user
type userRec struct {
	up, down         atomic.Int64 // total traffic
	pendUp, pendDown atomic.Int64 // traffic not collected yet
	chans            map[*channel]struct{}
	lastSeen         time.Time
}

// sessionRec is the books of a single session
type sessionRec struct {
	id, user, route, addr string
	since                 time.Time
	up, down              atomic.Int64
	chans                 map[*channel]struct{}
}

// channel is a live tunnel
type channel struct {
	tr      *tracker
	rec     *userRec
	sess    *sessionRec
	user    string
	session string
	route   string
	addr    string
	ip      string
	up      atomic.Int64
	down    atomic.Int64
	kick    func() // closes the client connection
}

// newTracker creates an empty tracker
func newTracker() *tracker {
	return &tracker{
		started:  time.Now(),
		users:    map[string]*userRec{},
		sessions: map[string]*sessionRec{},
		subs:     map[chan Event]struct{}{},
	}
}

// open registers a tunnel
func (t *tracker) open(user, session, route string, addr net.Addr, kick func()) *channel {
	a := ""
	if addr != nil {
		a = addr.String()
	}

	ip, _, err := net.SplitHostPort(a)
	if err != nil {
		ip = a
	}

	// tunnels without a session stand alone
	if session == "" {
		session = a
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	rec := t.users[user]
	if rec == nil {
		rec = &userRec{chans: map[*channel]struct{}{}}
		t.users[user] = rec
	}

	sess := t.sessions[session]
	if sess == nil {
		sess = &sessionRec{id: session, user: user, route: route, addr: a, since: time.Now(), chans: map[*channel]struct{}{}}
		t.sessions[session] = sess
	}

	ch := &channel{tr: t, rec: rec, sess: sess, user: user, session: session, route: route, addr: a, ip: ip, kick: kick}
	rec.chans[ch] = struct{}{}
	sess.chans[ch] = struct{}{}
	rec.lastSeen = time.Now()

	t.publish(Event{Type: EventConnect, User: user, Session: session, Route: route, Addr: a, At: rec.lastSeen, Online: len(rec.chans)})
	return ch
}

// done unregisters a tunnel
func (t *tracker) done(ch *channel) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(ch.rec.chans, ch)
	delete(ch.sess.chans, ch)
	if len(ch.sess.chans) == 0 {
		delete(t.sessions, ch.session)
	}
	ch.rec.lastSeen = time.Now()

	t.publish(Event{
		Type: EventDisconnect, User: ch.user, Session: ch.session, Route: ch.route, Addr: ch.addr,
		At: ch.rec.lastSeen, Usage: Usage{Up: ch.up.Load(), Down: ch.down.Load()}, Online: len(ch.rec.chans),
	})
}

// publish hands an event to subscribers, skipping those that are full, must be called with mu held
func (t *tracker) publish(ev Event) {
	for c := range t.subs {
		select {
		case c <- ev:
		default:
		}
	}
}

// userStats builds the stats of a user, must be called with mu held
func (t *tracker) userStats(uuid string, u *userRec) UserStats {
	st := UserStats{
		UUID:     uuid,
		Usage:    Usage{Up: u.up.Load(), Down: u.down.Load()},
		Channels: len(u.chans),
		Online:   len(u.chans) > 0,
		LastSeen: u.lastSeen,
	}

	sessions := map[string]struct{}{}
	for ch := range u.chans {
		sessions[ch.session] = struct{}{}
		if !slices.Contains(st.IPs, ch.ip) {
			st.IPs = append(st.IPs, ch.ip)
		}
	}

	slices.Sort(st.IPs)
	st.Sessions = len(sessions)
	return st
}

// victims collects the live tunnels of a user or a session
func (t *tracker) victims(chans func() map[*channel]struct{}) []*channel {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []*channel
	for ch := range chans() {
		out = append(out, ch)
	}
	return out
}

// addUp counts upload
func (c *channel) addUp(n int64) {
	c.up.Add(n)
	c.rec.up.Add(n)
	c.rec.pendUp.Add(n)
	c.sess.up.Add(n)
	c.tr.up.Add(n)
}

// addDown counts download
func (c *channel) addDown(n int64) {
	c.down.Add(n)
	c.rec.down.Add(n)
	c.rec.pendDown.Add(n)
	c.sess.down.Add(n)
	c.tr.down.Add(n)
}

// countConn counts what passes through a client connection
type countConn struct {
	net.Conn
	ch *channel
}

// Read reads from the client and counts it as upload
func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.ch.addUp(int64(n))
	}
	return n, err
}

// Write writes to the client and counts it as download
func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.ch.addDown(int64(n))
	}
	return n, err
}

// Stats returns server wide numbers
func (s *TurnableServer) Stats() ServerStats {
	t := s.tr
	t.mu.Lock()
	defer t.mu.Unlock()

	st := ServerStats{Started: t.started, Usage: Usage{Up: t.up.Load(), Down: t.down.Load()}, Sessions: len(t.sessions)}
	for _, u := range t.users {
		if len(u.chans) > 0 {
			st.Users++
			st.Channels += len(u.chans)
		}
	}
	return st
}

// Users lists every user seen since the server started
func (s *TurnableServer) Users() []UserStats {
	t := s.tr
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]UserStats, 0, len(t.users))
	for uuid, u := range t.users {
		out = append(out, t.userStats(uuid, u))
	}

	slices.SortFunc(out, func(a, b UserStats) int { return strings.Compare(a.UUID, b.UUID) })
	return out
}

// User returns the stats of a single user, false if the server never saw them
func (s *TurnableServer) User(uuid string) (UserStats, bool) {
	t := s.tr
	t.mu.Lock()
	defer t.mu.Unlock()

	u, ok := t.users[uuid]
	if !ok {
		return UserStats{UUID: uuid}, false
	}
	return t.userStats(uuid, u), true
}

// CollectUsage returns what each user moved since the previous call and resets the counters, idle users are left out
func (s *TurnableServer) CollectUsage() map[string]Usage {
	t := s.tr
	t.mu.Lock()
	defer t.mu.Unlock()

	out := map[string]Usage{}
	for uuid, u := range t.users {
		d := Usage{Up: u.pendUp.Swap(0), Down: u.pendDown.Swap(0)}
		if d.Up != 0 || d.Down != 0 {
			out[uuid] = d
		}
	}
	return out
}

// Sessions lists live sessions, oldest first
func (s *TurnableServer) Sessions() []SessionInfo {
	t := s.tr
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]SessionInfo, 0, len(t.sessions))
	for id, r := range t.sessions {
		out = append(out, SessionInfo{
			ID: id, User: r.user, Route: r.route, Addr: r.addr, Since: r.since,
			Usage: Usage{Up: r.up.Load(), Down: r.down.Load()}, Channels: len(r.chans),
		})
	}

	slices.SortFunc(out, func(a, b SessionInfo) int { return a.Since.Compare(b.Since) })
	return out
}

// KickUser closes every live tunnel of a user and returns how many it closed
func (s *TurnableServer) KickUser(uuid string) int {
	victims := s.tr.victims(func() map[*channel]struct{} {
		if u := s.tr.users[uuid]; u != nil {
			return u.chans
		}
		return nil
	})

	for _, ch := range victims {
		ch.kick()
	}
	return len(victims)
}

// KickSession closes every tunnel of a session and returns how many it closed
func (s *TurnableServer) KickSession(id string) int {
	victims := s.tr.victims(func() map[*channel]struct{} {
		if r := s.tr.sessions[id]; r != nil {
			return r.chans
		}
		return nil
	})

	for _, ch := range victims {
		ch.kick()
	}
	return len(victims)
}

// Subscribe streams tunnel events until cancel is called, a subscriber that falls behind misses events
func (s *TurnableServer) Subscribe(buffer int) (<-chan Event, func()) {
	t := s.tr
	c := make(chan Event, max(buffer, 1))

	t.mu.Lock()
	t.subs[c] = struct{}{}
	t.mu.Unlock()

	var once sync.Once
	return c, func() {
		once.Do(func() {
			t.mu.Lock()
			delete(t.subs, c)
			t.mu.Unlock()
			close(c)
		})
	}
}
