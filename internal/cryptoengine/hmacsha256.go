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
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256Provider implements HMAC-SHA-256
type HMACSHA256Provider struct{}

// NewHMACSHA256Provider creates a new HMAC-SHA-256 provider
func NewHMACSHA256Provider() *HMACSHA256Provider {
	return &HMACSHA256Provider{}
}

// Algorithm returns the algorithm name
func (p *HMACSHA256Provider) Algorithm() string {
	return "HMAC-SHA-256"
}

// KeySize returns the recommended key size (SHA-256 block size is 64 bytes)
func (p *HMACSHA256Provider) KeySize() int {
	return sha256.BlockSize // 64 bytes
}

// HMAC computes HMAC-SHA-256 of data
func (p *HMACSHA256Provider) HMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC verifies an HMAC-SHA-256
func (p *HMACSHA256Provider) VerifyHMAC(key, data, mac []byte) bool {
	expectedMAC := p.HMAC(key, data)
	return hmac.Equal(mac, expectedMAC)
}
