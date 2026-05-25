//go:build ignore

// export_proto_golden writes minimal NeoFS stable-marshal blobs for cross-language
// proto round-trip vectors. Run from neofs-sdk-go:
//
//	go run ../neofs-sdk-zig/scripts/export_proto_golden.go
package main

import (
	"os"
	"path/filepath"

	"github.com/nspcc-dev/neofs-sdk-go/proto/accounting"
	"github.com/nspcc-dev/neofs-sdk-go/proto/acl"
	"github.com/nspcc-dev/neofs-sdk-go/proto/audit"
	"github.com/nspcc-dev/neofs-sdk-go/proto/container"
	"github.com/nspcc-dev/neofs-sdk-go/proto/link"
	"github.com/nspcc-dev/neofs-sdk-go/proto/lock"
	"github.com/nspcc-dev/neofs-sdk-go/proto/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/proto/object"
	"github.com/nspcc-dev/neofs-sdk-go/proto/refs"
	"github.com/nspcc-dev/neofs-sdk-go/proto/reputation"
	"github.com/nspcc-dev/neofs-sdk-go/proto/session"
	"github.com/nspcc-dev/neofs-sdk-go/proto/status"
	"github.com/nspcc-dev/neofs-sdk-go/proto/storagegroup"
	"github.com/nspcc-dev/neofs-sdk-go/proto/subnet"
	"github.com/nspcc-dev/neofs-sdk-go/proto/tombstone"
)

type stableMessage interface {
	MarshaledSize() int
	MarshalStable([]byte)
}

func marshalStable(m stableMessage) []byte {
	b := make([]byte, m.MarshaledSize())
	m.MarshalStable(b)
	return b
}

func main() {
	outRoot := filepath.Join("..", "neofs-sdk-zig", "test", "vectors", "proto")
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		panic(err)
	}

	exports := []struct {
		domain string
		data   []byte
	}{
		{"accounting", marshalStable(&accounting.Decimal{Value: 1, Precision: 1})},
		{"acl", marshalStable(&acl.BearerToken_Body_TokenLifetime{Exp: 1, Nbf: 2, Iat: 3})},
		{"audit", marshalStable(&audit.DataAuditResult{AuditEpoch: 1})},
		{"container", marshalStable(&container.Container_Attribute{Key: "k", Value: "v"})},
		{"link", marshalStable(&link.Link_MeasuredObject{Size: 1})},
		{"lock", marshalStable(&lock.Lock{Members: []*refs.ObjectID{{Value: []byte{1}}}})},
		{"netmap", marshalStable(&netmap.Replica{Count: 1, Selector: "s"})},
		{"object", marshalStable(&object.Range{Offset: 1, Length: 2})},
		{"refs", marshalStable(&refs.Version{Major: 1, Minor: 2})},
		{"reputation", marshalStable(&reputation.PeerID{PublicKey: []byte{1}})},
		{"session", marshalStable(&session.XHeader{Key: "k", Value: "v"})},
		{"status", marshalStable(&status.Status{Code: 1, Message: "ok"})},
		{"storagegroup", marshalStable(&storagegroup.StorageGroup{ValidationDataSize: 1})},
		{"subnet", marshalStable(&subnet.SubnetInfo{Owner: &refs.OwnerID{Value: []byte{1}}})},
		{"tombstone", marshalStable(&tombstone.Tombstone{ExpirationEpoch: 1})},
	}

	for _, e := range exports {
		dir := filepath.Join(outRoot, e.domain)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		path := filepath.Join(dir, "roundtrip.bin")
		if err := os.WriteFile(path, e.data, 0o644); err != nil {
			panic(err)
		}
	}
}
