// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package ethtest

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/bal"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/utesting"
	"github.com/ethereum/go-ethereum/rlp"
)

// validateAccessListsResponse validates a BAL response shared by snap/2 and
// eth/71. Both protocols use the same positional response list where 0x80 marks
// an unavailable BAL.
func (s *Suite) validateAccessListsResponse(t *utesting.T, tc *accessListsTest, reqID, resID uint64, accessLists rlp.RawList[rlp.RawValue]) error {
	if resID != reqID {
		return fmt.Errorf("request id mismatch: got %d, want %d", resID, reqID)
	}

	// Check list length bounds.
	got := accessLists.Len()
	if got < tc.minEntries || got > tc.maxEntries {
		return fmt.Errorf("response has %d entries, want between %d and %d", got, tc.minEntries, tc.maxEntries)
	}

	// Build a map of request-index -> block so we can verify BAL hashes.
	blocks := make(map[int]*types.Block)
	for i, h := range tc.hashes {
		for _, b := range s.chain.blocks {
			if b.Hash() == h {
				blocks[i] = b
				break
			}
		}
	}

	// Build a set of positions that MUST be empty (for per-position checks).
	mustEmpty := make(map[int]struct{}, len(tc.mustBeEmptyAt))
	for _, p := range tc.mustBeEmptyAt {
		mustEmpty[p] = struct{}{}
	}
	head := s.chain.Head().Header()
	headRules := s.chain.config.Rules(head.Number, true, head.Time)

	// Iterate the response, validating each entry positionally.
	var (
		idx int
		it  = accessLists.ContentIterator()
	)
	for it.Next() {
		if idx >= len(tc.hashes) {
			return fmt.Errorf("response contains unexpected extra entry %d", idx)
		}
		raw := it.Value()

		// Empty entry: per spec, indicates BAL is unavailable for that block.
		if bytes.Equal(raw, rlp.EmptyString) {
			if !tc.expectAllEmpty && blocks[idx] != nil && blocks[idx].Header().BlockAccessListHash != nil {
				// Not a failure — the server is allowed to legitimately not
				// have the BAL. But we log it so the test output is diagnosable.
				t.Logf("    entry %d: server returned empty for known post-Amsterdam block %x", idx, tc.hashes[idx])
			}
			idx++
			continue
		}

		// Non-empty entry. If the requester asked for a block we do not know
		// about, receiving data here is a protocol violation.
		if tc.expectAllEmpty {
			return fmt.Errorf("entry %d: expected empty entry, got %d bytes of BAL data", idx, len(raw))
		}
		if _, required := mustEmpty[idx]; required {
			return fmt.Errorf("entry %d: position must be empty (unknown hash), got %d bytes of BAL data", idx, len(raw))
		}

		// Compute keccak256(rlp.encode(bal)) against the raw bytes actually
		// received on the wire, and compare to the header commitment. Hashing raw
		// bytes catches peers that send non-canonical BAL encodings.
		block, known := blocks[idx]
		rules := headRules
		if known && block.Header().BlockAccessListHash != nil {
			header := block.Header()
			rules = s.chain.config.Rules(header.Number, true, header.Time)
			have := crypto.Keccak256Hash(raw)
			want := *header.BlockAccessListHash
			if have != want {
				return fmt.Errorf("entry %d: BAL hash mismatch: have %x, want %x", idx, have, want)
			}
		}

		// Also decode and validate the BAL's internal structure: ordering of
		// accounts/slots/changes, code-size limits, etc. This catches malformed
		// responses even when we can't compare to a header hash.
		var accessList bal.BlockAccessList
		if err := rlp.DecodeBytes(raw, &accessList); err != nil {
			return fmt.Errorf("entry %d: invalid BAL RLP: %v", idx, err)
		}
		if err := accessList.Validate(rules); err != nil {
			return fmt.Errorf("entry %d: BAL failed validation: %v", idx, err)
		}
		idx++
	}

	// Sanity: iterator consumed exactly the reported number of entries.
	if idx != got {
		return fmt.Errorf("iterator visited %d entries, expected %d", idx, got)
	}
	return nil
}
