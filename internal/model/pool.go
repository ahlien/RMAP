package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"github.com/miekg/dns"
)

type RecordPool struct {
	Data sync.Map // map[string][]dns.RR
}

func (p *RecordPool) Store(rrs []dns.RR) string {
	if len(rrs) == 0 { return "" }
	s := ""
	for _, rr := range rrs { s += rr.String() }
	h := sha256.Sum256([]byte(s))
	hash := hex.EncodeToString(h[:])
	p.Data.LoadOrStore(hash, rrs)
	return hash
}