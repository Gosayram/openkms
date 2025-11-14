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

package cryptoengine

import (
	"testing"
)

func TestHMACSHA256_HMAC(t *testing.T) {
	provider := NewHMACSHA256Provider()

	key := []byte("test key for HMAC")
	data := []byte("test data")

	mac := provider.HMAC(key, data)
	if len(mac) != 32 {
		t.Errorf("Expected HMAC size 32 (SHA-256), got %d", len(mac))
	}
}

func TestHMACSHA256_VerifyHMAC(t *testing.T) {
	provider := NewHMACSHA256Provider()

	key := []byte("test key")
	data := []byte("test data")

	mac := provider.HMAC(key, data)

	// Verify correct MAC
	valid := provider.VerifyHMAC(key, data, mac)
	if !valid {
		t.Error("HMAC verification should succeed for correct MAC")
	}

	// Verify wrong MAC
	wrongMAC := []byte("wrong mac")
	valid = provider.VerifyHMAC(key, data, wrongMAC)
	if valid {
		t.Error("HMAC verification should fail for wrong MAC")
	}

	// Verify with wrong data
	valid = provider.VerifyHMAC(key, []byte("wrong data"), mac)
	if valid {
		t.Error("HMAC verification should fail for wrong data")
	}
}
