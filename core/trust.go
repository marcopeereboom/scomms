/*
 * Copyright (c) 2014 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/marcopeereboom/mcrypt"
	"github.com/syndtr/goleveldb/leveldb"
)

type Trust struct {
	db  *leveldb.DB
	mtx sync.RWMutex
}

func NewTrust(path string) (*Trust, error) {
	targetDir := path + "/trust/"
	err := os.MkdirAll(targetDir, 0700)
	if err != nil {
		return nil, err
	}

	t := Trust{}
	t.db, err = leveldb.OpenFile(targetDir, nil)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (t *Trust) Close() {
	t.db.Close()
}

type TrustRecord struct {
	PublicIdentity *mcrypt.PublicIdentity
	Inserted       time.Time         // database insertion
	LastUpdate     time.Time         // record update
	State          int               // record state
	FreeToUse      map[string]string // User definable key value pairs
}

const (
	StateInvalid = 0
	StateQueued  = 1
	StateDenied  = 2
	StateAllowed = 100
)

var (
	State = map[int]string{
		StateInvalid: "Invalid",
		StateQueued:  "Queued",
		StateDenied:  "Denied",
		StateAllowed: "Allowed",
	}
)

func (t *Trust) Update(id *mcrypt.Identity, tr *TrustRecord) error {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	tr.LastUpdate = time.Now()
	return t.put(id, tr)
}

// Store public identity in database
func (t *Trust) Add(id *mcrypt.Identity, trustee *mcrypt.PublicIdentity,
	state int, freeToUse map[string]string, overwrite bool) error {

	t.mtx.Lock()
	defer t.mtx.Unlock()

	// see if it already exists
	if overwrite == false {
		_, err := t.db.Get(trustee.Key[:], nil)
		if err == nil {
			return fmt.Errorf("public key already exists")
		}
	}

	tr := &TrustRecord{
		PublicIdentity: trustee,
		Inserted:       time.Now(),
		State:          state,
		FreeToUse:      freeToUse,
	}

	return t.put(id, tr)
}

func (t *Trust) put(id *mcrypt.Identity, tr *TrustRecord) error {
	// marshal so that we can encrypt
	payload, err := json.Marshal(tr)
	if err != nil {
		return err
	}

	// note that we are encrypting to self
	msg, err := id.Encrypt(id.PublicIdentity.Key, payload)
	if err != nil {
		return err
	}

	// marshall mcrypt.Message for db insertion
	dbPayload, err := msg.Marshal()
	if err != nil {
		return err
	}

	// plop it in db
	err = t.db.Put(tr.PublicIdentity.Key[:], dbPayload, nil)
	if err != nil {
		return err
	}

	return nil
}

// Get encrypted public identity from database
func (t *Trust) get(pubKey []byte) ([]byte, error) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	dbPayload, err := t.db.Get(pubKey, nil)
	if err != nil {
		return nil, err
	}
	return dbPayload, nil
}

// Decrypt record
func (t *Trust) decrypt(id *mcrypt.Identity,
	dbPayload []byte) (*TrustRecord, error) {

	// unmarshal mcrypt.Message
	msg, err := mcrypt.UnmarshalMessage(dbPayload)
	if err != nil {
		return nil, err
	}

	// note that we are decrypting from self
	ct, err := id.Decrypt(id.PublicIdentity.Key, msg)
	if err != nil {
		return nil, err
	}

	// recreate trust record
	tr := TrustRecord{}
	err = json.Unmarshal(ct, &tr)
	if err != nil {
		return nil, err
	}

	return &tr, nil
}

// Get public identity from database
func (t *Trust) Get(id *mcrypt.Identity,
	trustee *mcrypt.PublicIdentity) (*TrustRecord, error) {
	// get from db
	dbPayload, err := t.get(trustee.Key[:])
	if err != nil {
		return nil, err
	}

	return t.decrypt(id, dbPayload)
}

// Get all rust records.
func (t *Trust) GetAll(id *mcrypt.Identity) ([]*TrustRecord, error) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	array := make([]*TrustRecord, 0, 100)

	iter := t.db.NewIterator(nil, nil)
	for iter.Next() {
		//pubKey := iter.Key()
		dbPayload := iter.Value()
		tr, err := t.decrypt(id, dbPayload)
		if err != nil {
			return nil, err
		}
		array = append(array, tr)
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, err
	}

	return array, nil
}
