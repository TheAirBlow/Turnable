package common

import (
	"fmt"
	"reflect"
	"sync"
)

var (
	ConnectionsHolder RegistryHolder // Safe holder for connection.Handlers
	PlatformsHolder   RegistryHolder // Safe holder for platform.Handlers
	TransportsHolder  RegistryHolder // Safe holder for transport.Handlers
	ProtocolsHolder   RegistryHolder // Safe holder for protocol.Handlers
)

// RegistryItem represents a Registry item with a string ID
type RegistryItem interface {
	ID() string
}

// RegistryHolder represents a "holder" for a registry of any type
type RegistryHolder interface {
	List() []string
	Exists(name string) bool
}

// Registry represents a generic item registry addressed by a string ID
type Registry[T RegistryItem] struct {
	mu    sync.RWMutex
	items map[string]reflect.Type
}

// NewRegistry creates a new Registry for the specified type
func NewRegistry[T RegistryItem]() *Registry[T] {
	return &Registry[T]{
		items: make(map[string]reflect.Type),
	}
}

// Register registers the specified RegistryItem
func (r *Registry[T]) Register(item T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	itemType := reflect.TypeOf(item)
	if itemType == nil {
		panic("cannot register nil item")
	}
	if itemType.Kind() == reflect.Pointer {
		itemType = itemType.Elem()
	}
	r.items[item.ID()] = itemType
}

// Get fetches a RegistryItem by its string ID
func (r *Registry[T]) Get(name string) (T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	itemType, ok := r.items[name]
	if !ok {
		var zero T
		return zero, fmt.Errorf("item '%s' not found", name)
	}

	instance := reflect.New(itemType).Interface()
	item, ok := instance.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("item '%s' cannot be instantiated as requested type", name)
	}
	return item, nil
}

// List lists all RegistryItem string IDs
func (r *Registry[T]) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	return keys
}

// Exists checks whether there is a RegistryItem with the specified ID
func (r *Registry[T]) Exists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.items[name]
	return ok
}
