package protocache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/golang/protobuf/proto"
	logxi "github.com/mgutz/logxi/v1"
)

const separator = "|"

const TOO_BIG = 1024 * 200

// for another day.
//type protoFunc func(context.Context, proto.Message) (proto.Message, error)

// PC is the protocache base struct
type PC struct {
	Scope    string           // The global scope name for this instance of the protocache
	Memcache *memcache.Client // Canonical client.
	Logger   logxi.Logger
}

// New creates a new instance of the protocache client.
func New(scope string, servers ...string) *PC {
	client := memcache.New(servers...)

	if len(scope) == 0 || len(strings.TrimSpace(scope)) == 0 {
		scope = "Default"
	}

	logger := logxi.New("protocache")

	return &PC{
		Scope:    scope,
		Memcache: client,
		Logger:   logger,
	}
}

// func (pc PC) GetAndSet(primaryContext, SecondaryContext, key string, getter protoFunc) (proto.Message, error) {

// }

// Get will retrieve an entry from the cache and potentially return the result in the provided result.
func (pc PC) Get(primaryContext, secondaryContext, key string, result proto.Message) error {
	pc.Logger.Info("Get", "primaryContext", primaryContext, "secondaryContext", secondaryContext, "key", key)
	// First determine the key.
	encodedKey, err := pc.getSPSK(primaryContext, secondaryContext, key)
	if err != nil {
		return err
	}

	item, err := pc.Memcache.Get(encodedKey)
	if err != nil {
		return err
	}

	if item.Flags > 0 {
		// It is compressed
		// uncompressed
		item.Value, err = uncompressBytes(item.Value)
		if err != nil {
			return err
		}
	}

	err = proto.Unmarshal(item.Value, result)
	// Will be nil if no error
	return err
}

func (pc PC) Set(primaryContext, secondaryContext, key string, value proto.Message, expiration time.Duration) error {
	pc.Logger.Info("Set", "primaryContext", primaryContext, "secondaryContext", secondaryContext, "key", key, "Duration", expiration)
	encodedKey, err := pc.getSPSK(primaryContext, secondaryContext, key)
	if err != nil {
		return err
	}

	item := memcache.Item{
		Key:        encodedKey,
		Expiration: int32(expiration / time.Second),
	}

	protoBytes, err := proto.Marshal(value)
	if err != nil {
		return err
	}

	item.Value = protoBytes
	item.Flags = 0

	pc.Logger.Debug("Set", "Length before compression was", len(item.Value))
	if len(protoBytes) >= 1000 {
		cBytes, cErr := compressBytes(protoBytes)
		if cErr == nil {
			item.Value = cBytes
			item.Flags = 1
		}
	}
	pc.Logger.Debug("Set", "Length after compression was", len(item.Value))

	if len(item.Value) > TOO_BIG {
		return pc.Logger.Error("Set", "Item too Big", len(item.Value), "primaryContext", primaryContext, "secondaryContext", secondaryContext, "key", key)
	}

	err = pc.Memcache.Set(&item)
	// Will be nil if no err
	return err
}

func uncompressBytes(value []byte) ([]byte, error) {
	decompressor, err := gzip.NewReader(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}

	result, err := ioutil.ReadAll(decompressor)
	if err != nil {
		return nil, err
	}

	if err := decompressor.Close(); err != nil {
		return nil, err
	}

	return result, nil
}

func compressBytes(value []byte) ([]byte, error) {
	targetBuffer := bytes.NewBuffer(nil)
	compressor := gzip.NewWriter(targetBuffer)

	_, err := compressor.Write(value)
	if err != nil {
		return nil, err
	}

	err = compressor.Flush()
	if err != nil {
		return nil, err
	}

	err = compressor.Close()
	if err != nil {
		return nil, err
	}

	return targetBuffer.Bytes(), nil
}

// getSPSK is used to generate a Scoped, Primary, Secondary, Key value.
func (pc PC) getSPSK(primaryContext, secondaryContext, key string) (string, error) {
	pc.Logger.Info("getSPSK", "Scope", pc.Scope, "primaryContext", primaryContext, "secondaryContext", secondaryContext, "Key", key)
	// First we must get the versioned key for the scope.
	scopeAlone, err := pc.getVersionedKey(pc.Scope)
	if err != nil {
		return "", err
	}
	pc.Logger.Debug("getSPSK", "Scope", pc.Scope, "VersionedScope", scopeAlone)

	// Then we must get the versioned key for the primary context.
	scopeAndPrimary, err := pc.getVersionedKey(pc.ConcatKeys(scopeAlone, primaryContext))
	if err != nil {
		return "", err
	}
	pc.Logger.Debug("getSPSK", "scopeAndPrimary", scopeAndPrimary, "VersionedScope", scopeAlone)

	// Then we must get the versioned key for the secondary context.
	primaryAndSecondary, err := pc.getVersionedKey(pc.ConcatKeys(scopeAndPrimary, secondaryContext))
	if err != nil {
		return "", err
	}

	// Finally we must get the NON versioned key for the key.
	fullScopeAndKey := pc.HashKey(primaryAndSecondary, key)
	if err != nil {
		return "", err
	}

	return fullScopeAndKey, nil

}

func (pc PC) initCounter(key string) (uint64, error) {
	// Ok we got here because the value is either bad
	// or missing.
	pc.Logger.Info("initCounter", "Key", key)
	err := pc.Memcache.Set(&memcache.Item{Key: key, Value: []byte("1")})
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (pc PC) valueToCounter(value []byte) (uint64, error) {
	pc.Logger.Info("ValueToCounter", "Value", value)
	counter, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil {
		return 0, err
	}
	return counter, nil
}

func (pc PC) getKeyVersion(key string) (uint64, error) {
	pc.Logger.Info("GetKeyVersion", "Key", key)
	result, err := pc.Memcache.Get(key)
	if err != nil {
		switch err {
		case memcache.ErrCacheMiss:
			// Not in the cache, go ahead and initialize.
			return pc.initCounter(key)
		default:
			return 0, err
		}
	}
	return pc.valueToCounter(result.Value)
}

func (pc PC) getVersionedKey(key string) (string, error) {
	pc.Logger.Info("getVersionedKey", "Key", key)
	keyToGet := pc.HashKey(key)
	counter, err := pc.getKeyVersion(keyToGet)

	if err != nil {
		// This is an invalid counter.
		// Initialize it
		counter, err = pc.initCounter(keyToGet)
		if err != nil {
			return "", err
		}
		// This return is not necessary.
		// return pc.VersionedKey(keyToGet, counter), nil
	}
	return pc.VersionedKey(keyToGet, counter), nil
}

// HashKey is the receiver function which hashes the given key.
func (pc PC) HashKey(keys ...string) string {
	pc.Logger.Info("HashKey", "Keys", keys)
	stringToHash := strings.Join(keys, separator)
	hash := sha256.Sum256([]byte(stringToHash))
	pc.Logger.Debug("HashKey", "Key", stringToHash, "Hash", hex.EncodeToString(hash[:]))
	return hex.EncodeToString(hash[:])
	// return key
}

// VersionedKey returns the hashed key given the internal separator and the provided version.
func (pc PC) VersionedKey(key string, version uint64) string {
	pc.Logger.Info("VersionedKey", "Key", key, "Version", version)
	stringToHash := fmt.Sprintf("%s%s%d", key, separator, version)
	return pc.HashKey(stringToHash)
}

func (pc PC) invalidateScope() {
	pc.Logger.Info("invalidateScope", "Scope Key", pc.Scope)
	scopeKey := pc.HashKey(pc.Scope)
	pc.invalidateKey(scopeKey)
}

func (pc PC) invalidatePrimary(primaryContext string) {
	pc.Logger.Info("invalidatePrimary", "primaryContext", primaryContext)
	scopeAlone, err := pc.getVersionedKey(pc.Scope)
	if err != nil {
		return
	}

	// This gets us the key to invalidate.
	scopeAndPrimary := pc.ConcatKeys(scopeAlone, primaryContext)
	pc.invalidateKey(scopeAndPrimary)
	return
}

func (pc PC) invalidateSecondary(primaryContext, secondaryContext string) {
	pc.Logger.Info("invalidateSecondary", "primaryContext", primaryContext, "secondaryContext", secondaryContext)
	scopeAlone, err := pc.getVersionedKey(pc.Scope)
	if err != nil {
		return
	}

	// Then we must get the versioned key for the primary context.
	scopeAndPrimary, err := pc.getVersionedKey(pc.ConcatKeys(scopeAlone, primaryContext))
	if err != nil {
		return
	}

	primaryAndSecondary := pc.ConcatKeys(scopeAndPrimary, secondaryContext)
	pc.invalidateKey(primaryAndSecondary)
	return
}

// invalidateKey is used to increment the specified increment key.
func (pc PC) invalidateKey(key string) {
	pc.Logger.Info("InvalidateKey", "Invalidating Key", key)
	_, err := pc.Memcache.Increment(key, 1)
	if err != nil {
		pc.Logger.Warn("InvalidateKey", "Unable to invalidate key", err.Error())
	}
	return

}

// ConcatKeys is used to appropriately concatenate keys using the internally defined separator.
func (pc PC) ConcatKeys(keys ...string) string {
	pc.Logger.Info("ConcatKeys", "Keys", keys)
	return strings.Join(keys, separator)
}
