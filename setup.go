package routealias

import (
	"fmt"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

type Config struct {
	host            string
	alias_name      string
	api_key         string
	api_secret      string
	skip_verify     bool
	whitelist_path  string
	flush_on_start  bool
	wait_for_record bool
	kill_state      bool
}

// init registers this plugin.
func init() { plugin.Register("routealias", setup) }

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "on", "yes", "1":
		return true, nil
	case "false", "off", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q (expected on/off, true/false, yes/no, 1/0)", s)
	}
}

func setup(c *caddy.Controller) error {
	cfg := Config{}

	if c.Next() { // Ignore "example" and give us the next token.
		for c.NextBlock() {
			switch c.Val() {
			case "host":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				cfg.host = args[0]
			case "api_key":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				cfg.api_key = args[0]
			case "api_secret":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				cfg.api_secret = args[0]
			case "alias_name":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				cfg.alias_name = args[0]
			case "skip_verify":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				v, err := parseBool(args[0])
				if err != nil {
					return c.Errf("skip_verify: %v", err)
				}
				cfg.skip_verify = v
			case "whitelist_path":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				cfg.whitelist_path = args[0]
			case "flush_on_start":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				v, err := parseBool(args[0])
				if err != nil {
					return c.Errf("flush_on_start: %v", err)
				}
				cfg.flush_on_start = v
			case "kill_state":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				v, err := parseBool(args[0])
				if err != nil {
					return c.Errf("kill_state: %v", err)
				}
				cfg.kill_state = v
			case "wait_for_record":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				v, err := parseBool(args[0])
				if err != nil {
					return c.Errf("wait_for_record: %v", err)
				}
				cfg.wait_for_record = v
			}
		}
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return NewRouteAlias(next, cfg)
	})

	// All OK, return a nil error.
	return nil
}
