// Copyright 2025 Gosayram Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ha

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// defaultStickySessionCookieName is the default cookie name for sticky sessions
	defaultStickySessionCookieName = "openkms_session"
	// defaultStickySessionTTL is the default TTL for sticky sessions
	defaultStickySessionTTL = 24 * time.Hour
	// defaultStickySessionCleanupInterval is the default interval for cleaning up expired sessions
	defaultStickySessionCleanupInterval = 1 * time.Hour
	// defaultSessionIDSize is the default size for session ID in bytes
	defaultSessionIDSize = 32
)

// StickySessionManager manages sticky client sessions
type StickySessionManager struct {
	nodeID        string
	cookieName    string
	ttl           time.Duration
	sessions      map[string]*Session
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	cleanupStop   chan struct{}
	cleanupWg     sync.WaitGroup
}

// Session represents a sticky session
type Session struct {
	ID        string
	NodeID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

// StickySessionConfig holds configuration for sticky sessions
type StickySessionConfig struct {
	NodeID     string
	CookieName string
	TTL        time.Duration
}

// NewStickySessionManager creates a new sticky session manager
func NewStickySessionManager(config StickySessionConfig) (*StickySessionManager, error) {
	if config.NodeID == "" {
		return nil, fmt.Errorf("node ID is required")
	}

	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = defaultStickySessionCookieName
	}

	ttl := config.TTL
	if ttl == 0 {
		ttl = defaultStickySessionTTL
	}

	ssm := &StickySessionManager{
		nodeID:      config.NodeID,
		cookieName:  cookieName,
		ttl:         ttl,
		sessions:    make(map[string]*Session),
		cleanupStop: make(chan struct{}),
	}

	// Start cleanup goroutine
	ssm.cleanupTicker = time.NewTicker(defaultStickySessionCleanupInterval)
	ssm.cleanupWg.Add(1)
	go ssm.cleanupExpiredSessions()

	return ssm, nil
}

// GetOrCreateSession gets an existing session or creates a new one
func (ssm *StickySessionManager) GetOrCreateSession(r *http.Request) (*Session, error) {
	// Try to get existing session from cookie
	cookie, err := r.Cookie(ssm.cookieName)
	if err == nil && cookie.Value != "" {
		session := ssm.GetSession(cookie.Value)
		if session != nil && session.NodeID == ssm.nodeID {
			// Update last seen
			ssm.mu.Lock()
			session.LastSeen = time.Now()
			ssm.mu.Unlock()
			return session, nil
		}
	}

	// Create new session
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		NodeID:    ssm.nodeID,
		CreatedAt: now,
		ExpiresAt: now.Add(ssm.ttl),
		LastSeen:  now,
	}

	ssm.mu.Lock()
	ssm.sessions[sessionID] = session
	ssm.mu.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID
func (ssm *StickySessionManager) GetSession(sessionID string) *Session {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()

	session, exists := ssm.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil
	}

	return session
}

// SetSessionCookie sets the session cookie in the response
func (ssm *StickySessionManager) SetSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     ssm.cookieName,
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
		MaxAge:   int(ssm.ttl.Seconds()),
	}

	http.SetCookie(w, cookie)
}

// DeleteSession deletes a session
func (ssm *StickySessionManager) DeleteSession(sessionID string) {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	delete(ssm.sessions, sessionID)
}

// DeleteSessionCookie deletes the session cookie
func (ssm *StickySessionManager) DeleteSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     ssm.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}

	http.SetCookie(w, cookie)
}

// cleanupExpiredSessions periodically cleans up expired sessions
func (ssm *StickySessionManager) cleanupExpiredSessions() {
	defer ssm.cleanupWg.Done()

	for {
		select {
		case <-ssm.cleanupStop:
			return
		case <-ssm.cleanupTicker.C:
			ssm.mu.Lock()
			now := time.Now()
			for id, session := range ssm.sessions {
				if now.After(session.ExpiresAt) {
					delete(ssm.sessions, id)
				}
			}
			ssm.mu.Unlock()
		}
	}
}

// Close closes the sticky session manager
func (ssm *StickySessionManager) Close() error {
	ssm.cleanupTicker.Stop()
	close(ssm.cleanupStop)
	ssm.cleanupWg.Wait()

	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	ssm.sessions = make(map[string]*Session)
	return nil
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	b := make([]byte, defaultSessionIDSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
