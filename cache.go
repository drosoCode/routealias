package routealias

import "sync"

type Cache struct {
	data map[string]struct{}
	lock sync.RWMutex
}

func NewCache() Cache {
	return Cache{
		data: map[string]struct{}{},
		lock: sync.RWMutex{},
	}
}

func (c *Cache) Exists(key string) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	_, ok := c.data[key]
	return ok
}

func (c *Cache) Add(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.data[key] = struct{}{}
}
