// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"resenje.org/singleflight"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

var (
	ErrNotFound = errors.New("not found")
)

type PeerLister interface {
	List(ctx context.Context, opts ...netbird.PeersListOption) ([]api.Peer, error)
}

type PeerStore struct {
	peerLister  PeerLister
	getGroup    *singleflight.Group[string, api.Peer]
	cacheMx     sync.RWMutex
	evictMx     sync.Mutex
	cache       map[string]api.Peer
	lastUpdated map[string]time.Time
	cacheTTL    time.Duration
}

func NewPeerStore(peerLister PeerLister) *PeerStore {
	return &PeerStore{
		peerLister:  peerLister,
		getGroup:    &singleflight.Group[string, api.Peer]{},
		cache:       map[string]api.Peer{},
		lastUpdated: map[string]time.Time{},
		cacheTTL:    15 * time.Second,
	}
}

func (p *PeerStore) Get(ctx context.Context, ip string) (api.Peer, error) {
	p.evictCache()

	peer, _, err := p.getGroup.Do(ctx, ip, func(ctx context.Context) (api.Peer, error) {
		p.cacheMx.RLock()
		if peer, ok := p.cache[ip]; ok {
			if time.Since(p.lastUpdated[ip]) < p.cacheTTL {
				p.cacheMx.RUnlock()
				return peer, nil
			}
		}
		p.cacheMx.RUnlock()

		peers, err := p.peerLister.List(ctx, netbird.PeerIPFilter(ip))
		if err != nil {
			return api.Peer{}, err
		}
		if len(peers) == 0 {
			return api.Peer{}, ErrNotFound
		}
		if len(peers) > 1 {
			return api.Peer{}, fmt.Errorf("receive more than one peer for ip %s", ip)
		}

		peer := peers[0]
		p.cacheMx.Lock()
		p.cache[ip] = peer
		p.lastUpdated[ip] = time.Now()
		p.cacheMx.Unlock()
		return peer, nil
	})
	if err != nil {
		return api.Peer{}, err
	}
	return peer, nil
}

func (p *PeerStore) evictCache() {
	if !p.evictMx.TryLock() {
		return
	}
	defer p.evictMx.Unlock()

	p.cacheMx.Lock()
	defer p.cacheMx.Unlock()
	for k := range p.cache {
		if time.Since(p.lastUpdated[k]) < p.cacheTTL {
			continue
		}
		delete(p.cache, k)
		delete(p.lastUpdated, k)
	}
}
