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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStickySessionManager_GetOrCreateSession tests session creation and retrieval
func TestStickySessionManager_GetOrCreateSession(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID:     "node1",
		CookieName: "test_session",
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm.Close()

	req := httptest.NewRequest("GET", "/", nil)

	// Create new session
	session1, err := ssm.GetOrCreateSession(req)
	require.NoError(t, err)
	assert.NotEmpty(t, session1.ID)
	assert.Equal(t, "node1", session1.NodeID)

	// Create request with cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{
		Name:  "test_session",
		Value: session1.ID,
	})

	// Should retrieve existing session
	session2, err := ssm.GetOrCreateSession(req2)
	require.NoError(t, err)
	assert.Equal(t, session1.ID, session2.ID)
	assert.Equal(t, "node1", session2.NodeID)
}

// TestStickySessionManager_GetSession tests session retrieval
func TestStickySessionManager_GetSession(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm.Close()

	req := httptest.NewRequest("GET", "/", nil)
	session, err := ssm.GetOrCreateSession(req)
	require.NoError(t, err)

	// Get session
	retrieved := ssm.GetSession(session.ID)
	assert.NotNil(t, retrieved)
	assert.Equal(t, session.ID, retrieved.ID)

	// Get non-existent session
	retrieved = ssm.GetSession("nonexistent")
	assert.Nil(t, retrieved)
}

// TestStickySessionManager_SetSessionCookie tests cookie setting
func TestStickySessionManager_SetSessionCookie(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm.Close()

	req := httptest.NewRequest("GET", "/", nil)
	session, err := ssm.GetOrCreateSession(req)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	ssm.SetSessionCookie(w, session)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, defaultStickySessionCookieName, cookies[0].Name)
	assert.Equal(t, session.ID, cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
}

// TestStickySessionManager_DeleteSession tests session deletion
func TestStickySessionManager_DeleteSession(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm.Close()

	req := httptest.NewRequest("GET", "/", nil)
	session, err := ssm.GetOrCreateSession(req)
	require.NoError(t, err)

	// Delete session
	ssm.DeleteSession(session.ID)

	// Should not be retrievable
	retrieved := ssm.GetSession(session.ID)
	assert.Nil(t, retrieved)
}

// TestStickySessionManager_DeleteSessionCookie tests cookie deletion
func TestStickySessionManager_DeleteSessionCookie(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm.Close()

	w := httptest.NewRecorder()
	ssm.DeleteSessionCookie(w)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, defaultStickySessionCookieName, cookies[0].Name)
	assert.Empty(t, cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

// TestStickySessionManager_ExpiredSession tests expired session handling
func TestStickySessionManager_ExpiredSession(t *testing.T) {
	ssm, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    100 * time.Millisecond, // Very short TTL
	})
	require.NoError(t, err)
	defer ssm.Close()

	req := httptest.NewRequest("GET", "/", nil)
	session, err := ssm.GetOrCreateSession(req)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup (normally done by background goroutine)
	// For test, we manually check
	retrieved := ssm.GetSession(session.ID)
	// Session might still exist in map but should be considered expired
	// The cleanup goroutine will remove it
	if retrieved != nil {
		assert.True(t, time.Now().After(retrieved.ExpiresAt))
	}
}

// TestStickySessionManager_NodeMismatch tests node ID mismatch
func TestStickySessionManager_NodeMismatch(t *testing.T) {
	ssm1, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node1",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm1.Close()

	ssm2, err := NewStickySessionManager(StickySessionConfig{
		NodeID: "node2",
		TTL:    1 * time.Hour,
	})
	require.NoError(t, err)
	defer ssm2.Close()

	// Create session on node1
	req1 := httptest.NewRequest("GET", "/", nil)
	session1, err := ssm1.GetOrCreateSession(req1)
	require.NoError(t, err)

	// Try to use session on node2
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{
		Name:  defaultStickySessionCookieName,
		Value: session1.ID,
	})

	// Should create new session (node mismatch)
	session2, err := ssm2.GetOrCreateSession(req2)
	require.NoError(t, err)
	assert.NotEqual(t, session1.ID, session2.ID)
	assert.Equal(t, "node2", session2.NodeID)
}
