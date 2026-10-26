// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lets_encrypt_state "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/s2sm/state/services/lets_encrypt_state"
	letsencrypt_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	host_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/host"
)

// fakeMirror captures the WatchStatus listener Run installs, so a test can play
// the kernel Watch breaking and coming back.
type fakeMirror struct {
	listener func(lets_encrypt_state.WatchStatus)
}

func (f *fakeMirror) SetWatchStatusListener(l func(lets_encrypt_state.WatchStatus)) { f.listener = l }

func (f *fakeMirror) status(retrying bool) {
	f.listener(lets_encrypt_state.WatchStatus{WatchName: "WatchCertData", Retrying: retrying, UpdatedAt: time.Now()})
}

// A kernel restart empties the LetsEncryptState mirror and breaks the Watch on
// it. When the Watch comes back, the certificate this process last stored must
// be written to kernel again at once, not at the next renewal tick (up to an
// hour, all of it with the gateway serving the cluster-CA certificate).
func TestKernelWatchReconnectRemirrorsTheCertificate(t *testing.T) {
	installTestIssuer(t, newSigningIssuer(t))
	hostname := fmt.Sprintf("remirror-%d.example.test", time.Now().UnixNano())

	fake := &fakeCertData{}
	mirror := &fakeMirror{}
	cm := &CertManager{
		cfg: &letsencrypt_pb.Config{
			LetsEncryptEmail:            "admin@example.test",
			HttpListener:                &host_pb.Host{Host: "127.0.0.1", Port: 0},
			RenewalCheckIntervalSeconds: 3600,
		},
		hostnames:  []string{hostname},
		storage:    NewStorage(),
		certData:   fake,
		mirror:     mirror,
		certRecord: &fakeCertRecord{},
		certSetID:  certSetID([]string{hostname}),
	}
	cm.storage.SetAccountStoreHook(cm.persistAccount)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	stored := waitForStoredCert(t, fake, 15*time.Second)
	if mirror.listener == nil {
		t.Fatal("Run did not install a Watch status listener")
	}
	before := len(fake.writes())

	// The first healthy status is the boot, not a reconnect: nothing extra.
	mirror.status(false)
	time.Sleep(200 * time.Millisecond)
	if n := len(fake.writes()); n != before {
		t.Fatalf("a healthy status at boot caused %d extra kernel write(s)", n-before)
	}

	// The Watch breaks (kernel restarting) and comes back.
	mirror.status(true)
	mirror.status(false)
	deadline := time.Now().Add(5 * time.Second)
	for len(fake.writes()) == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	writes := fake.writes()
	if len(writes) != before+1 {
		t.Fatalf("kernel writes after reconnect = %d, want %d", len(writes), before+1)
	}
	if !proto.Equal(writes[len(writes)-1], stored) {
		t.Fatal("the re-mirrored certificate is not the one last stored")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}
