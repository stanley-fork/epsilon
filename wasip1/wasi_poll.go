// Copyright 2025 Google LLC
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

//go:build unix

package wasip1

import (
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/ziggy42/epsilon/epsilon"
)

const subclockFlagsSubscriptionClockAbstime uint16 = 1 << 0

const (
	eventTypeClock   uint8 = 0
	eventTypeFdRead  uint8 = 1
	eventTypeFdWrite uint8 = 2
)

type subscriptionClock struct {
	clockId   uint32
	timeout   uint64
	precision uint64
	flags     uint16
}

type subscriptionFdReadwrite struct {
	fd uint32
}

type subscription struct {
	userData         uint64
	subscriptionType uint8
	// Padding ensures the Body field starts at offset 16 (8-byte aligned).
	// In C, the union after a u8 field would be padded to maintain alignment.
	// Without this, Body would start at offset 9, but it needs 8-byte alignment
	// because it contains u64 fields. So we add 7 bytes of padding (9 + 7 = 16).
	_ [7]byte
	// body contains the union of SubscriptionClock and SubscriptionFdReadwrite.
	body [32]byte
}

type eventFdReadwrite struct {
	nBytes uint64
	flags  uint16
}

type event struct {
	userData    uint64
	errorCode   int16 // u16 in WASI spec, not u32
	eventType   uint8
	fdReadWrite eventFdReadwrite
}

// parseSubscription reads a Subscription struct from memory.
func parseSubscription(
	memory *epsilon.Memory,
	offset uint32,
) (subscription, error) {
	data, err := memory.Get(0, offset, uint32(unsafe.Sizeof(subscription{})))
	if err != nil {
		return subscription{}, err
	}

	var sub subscription
	sub.userData = binary.LittleEndian.Uint64(data[0:8])
	sub.subscriptionType = data[8]
	copy(sub.body[:], data[16:48])
	return sub, nil
}

// parseSubscriptionClock extracts clock subscription fields from the body.
func parseSubscriptionClock(body [32]byte) subscriptionClock {
	return subscriptionClock{
		clockId: binary.LittleEndian.Uint32(body[0:4]),
		// body[4:8] is padding
		timeout:   binary.LittleEndian.Uint64(body[8:16]),
		precision: binary.LittleEndian.Uint64(body[16:24]),
		flags:     binary.LittleEndian.Uint16(body[24:26]),
	}
}

// parseSubscriptionFdReadwrite extracts FD subscription fields from the body.
func parseSubscriptionFdReadwrite(body [32]byte) subscriptionFdReadwrite {
	return subscriptionFdReadwrite{
		fd: binary.LittleEndian.Uint32(body[0:4]),
	}
}

// writeEvent writes an Event struct to memory.
func writeEvent(memory *epsilon.Memory, offset uint32, event event) error {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[0:8], event.userData)
	binary.LittleEndian.PutUint16(data[8:10], uint16(event.errorCode))
	data[10] = event.eventType
	binary.LittleEndian.PutUint64(data[16:24], event.fdReadWrite.nBytes)
	binary.LittleEndian.PutUint16(data[24:26], event.fdReadWrite.flags)
	return memory.Set(0, offset, data)
}

const maxSubscriptions = 4096

// handleClockSubscription processes a clock subscription and returns the
// timeout duration and an event. If the clock ID is invalid, it returns an
// error event.
func (w *WasiModule) handleClockSubscription(
	sub subscription,
) (time.Duration, event) {
	clockSub := parseSubscriptionClock(sub.body)
	isAbsoluteTime := clockSub.flags&subclockFlagsSubscriptionClockAbstime != 0

	var timeout int64
	if isAbsoluteTime {
		now, errCode := getTimestamp(w.monotonicClockStartNs, clockSub.clockId)
		if errCode != errnoSuccess {
			return 0, event{
				userData:  sub.userData,
				errorCode: int16(errnoInval),
				eventType: eventTypeClock,
			}
		}
		timeout = max(int64(clockSub.timeout)-now, 0)
	} else {
		timeout = int64(clockSub.timeout)
	}

	event := event{
		userData:  sub.userData,
		errorCode: int16(errnoSuccess),
		eventType: eventTypeClock,
	}
	return time.Duration(timeout), event
}

// handleFdSubscription processes an FD read/write subscription and returns an
// event if the FD is ready, or nil if it's not ready yet.
func (w *WasiModule) handleFdSubscription(sub subscription) *event {
	fdSub := parseSubscriptionFdReadwrite(sub.body)

	fd, errCode := w.fs.getFileOrDir(int32(fdSub.fd), RightsPollFdReadwrite)
	if errCode != errnoSuccess {
		return &event{
			userData:  sub.userData,
			errorCode: int16(errCode),
			eventType: sub.subscriptionType,
		}
	}

	switch fdSub.fd {
	case 0: // stdin is readable but not writable
		if sub.subscriptionType != eventTypeFdRead {
			return nil
		}
	case 1, 2: // stdout/stderr are writable but not readable
		if sub.subscriptionType != eventTypeFdWrite {
			return nil
		}
	}

	var nbytes uint64
	if fd.fileType == fileTypeRegularFile {
		if info, err := fd.file.Stat(); err == nil {
			nbytes = uint64(info.Size())
		}
	}

	return &event{
		userData:  sub.userData,
		errorCode: int16(errnoSuccess),
		eventType: sub.subscriptionType,
		fdReadWrite: eventFdReadwrite{
			nBytes: nbytes,
			// TODO: Implement proper hangup detection using syscall.Select or
			// unix.Poll to set eventRwFlagsFdReadwriteHangup when appropriate.
			flags: 0,
		},
	}
}

func (w *WasiModule) pollOneoff(
	memory *epsilon.Memory,
	inPtr, outPtr, nsubscriptions, neventsPtr int32,
) int32 {
	if nsubscriptions <= 0 || nsubscriptions > maxSubscriptions {
		return errnoInval
	}

	subscriptions := make([]subscription, nsubscriptions)
	for i := range nsubscriptions {
		offset := uint32(inPtr) + uint32(i)*uint32(unsafe.Sizeof(subscription{}))
		sub, err := parseSubscription(memory, offset)
		if err != nil {
			return errnoFault
		}
		subscriptions[i] = sub
	}

	events := make([]event, 0, nsubscriptions)
	var sleepDuration time.Duration
	var clockEvents []event

	for _, sub := range subscriptions {
		switch sub.subscriptionType {
		case eventTypeClock:
			timeout, clockEvent := w.handleClockSubscription(sub)
			if clockEvent.errorCode != int16(errnoSuccess) {
				events = append(events, clockEvent)
				continue
			}
			sleepDuration = max(sleepDuration, timeout)
			clockEvents = append(clockEvents, clockEvent)
		case eventTypeFdRead, eventTypeFdWrite:
			if fdEvent := w.handleFdSubscription(sub); fdEvent != nil {
				events = append(events, *fdEvent)
			}
		default:
			events = append(events, event{
				userData:  sub.userData,
				errorCode: int16(errnoInval),
				eventType: sub.subscriptionType,
			})
		}
	}

	// Determine if we need to sleep
	// Only sleep if there are no immediately ready FD events
	if sleepDuration > 0 && len(events) == 0 {
		// No FD events are ready, so we sleep and then return clock events
		time.Sleep(sleepDuration)
		events = append(events, clockEvents...)
	}
	// If there ARE ready FD events, we don't sleep and don't return clock events

	// Write events to output memory
	for i, e := range events {
		offset := uint32(outPtr) + uint32(i)*uint32(unsafe.Sizeof(event{}))
		if err := writeEvent(memory, offset, e); err != nil {
			return errnoFault
		}
	}

	err := memory.StoreUint32(0, uint32(neventsPtr), uint32(len(events)))
	if err != nil {
		return errnoFault
	}
	return errnoSuccess
}
