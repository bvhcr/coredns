package eccentric

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const (
	pluginName = "eccentric" // erratic
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	e, err := parseErratic(c)
	if err != nil {
		return plugin.Error("erratic", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return e
	})

	return nil
}

func parseErratic(c *caddy.Controller) (*Eccentric, error) {
	a := &ACL{}
	e := &Eccentric{drop: 2, acl: a}
	drop := false // true if we've seen the drop keyword

	for c.Next() { // 'erratic'
		r := rule{}
		args := c.RemainingArgs()
		r.zones = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)

		for c.NextBlock() {
			p := policy{}
			p.qtypes = make(map[uint16]struct{})

			// hasTypeSection := false
			// hasNetSection := false

			switch c.Val() {
			case "drop":
				args := c.RemainingArgs()
				if len(args) > 1 {
					return nil, c.ArgErr()
				}

				if len(args) == 0 {
					continue
				}

				amount, err := strconv.ParseInt(args[0], 10, 32)
				if err != nil {
					return nil, err
				}
				if amount < 0 {
					return nil, fmt.Errorf("illegal amount value given %q", args[0])
				}
				e.drop = uint64(amount)
				drop = true
			case "delay":
				args := c.RemainingArgs()
				if len(args) > 2 {
					return nil, c.ArgErr()
				}

				// Defaults.
				e.delay = 2
				e.duration = 100 * time.Millisecond
				if len(args) == 0 {
					continue
				}

				amount, err := strconv.ParseInt(args[0], 10, 32)
				if err != nil {
					return nil, err
				}
				if amount < 0 {
					return nil, fmt.Errorf("illegal amount value given %q", args[0])
				}
				e.delay = uint64(amount)

				if len(args) > 1 {
					duration, err := time.ParseDuration(args[1])
					if err != nil {
						return nil, err
					}
					e.duration = duration
				}
			case "truncate":
				args := c.RemainingArgs()
				if len(args) > 1 {
					return nil, c.ArgErr()
				}

				if len(args) == 0 {
					continue
				}

				amount, err := strconv.ParseInt(args[0], 10, 32)
				if err != nil {
					return nil, err
				}
				if amount < 0 {
					return nil, fmt.Errorf("illegal amount value given %q", args[0])
				}
				e.truncate = uint64(amount)
			case "large":
				e.large = true
			case "allow", "block", "filter", "phantom", "limit": // acl
				switch c.Val() {
				case "allow":
					p.action = permitAndlog
				case "block":
					p.action = forbidAndlog
				case "filter":
					p.action = filterAndlog
				case "phantom":
					p.action = phantomAndLog
				case "limit":
					p.action = limitAndlog
				default:
					panic(c.Val())
				}

				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, errors.New(
						"at least one type must be listed")
				}
				// o.types = make(typeMap, len(args))
				for _, a := range args {
					if a == "*" {
						p.qtypes[dns.TypeNone] = struct{}{}
						break
					}

					t, ok := dns.StringToType[strings.ToUpper(a)]
					if !ok {
						return nil,
							fmt.Errorf("invalid type %q", // acl/setup.go:97
								a)
					}
					// e.types[t] = true
					p.qtypes[t] = struct{}{}

				}
				/*
					case "block": // acl
						e.large = true
					case "filter": // acl
						e.large = true
				*/
				r.policies = append(r.policies, p)
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}

			/*
				// optional `type` section means all record types.
				if !hasTypeSection {
					p.qtypes[dns.TypeNone] = struct{}{}
				}
			*/

		}
		a.Rules = append(a.Rules, r)
	}
	if (e.delay > 0 || e.truncate > 0) && !drop { // delay is set, but we've haven't seen a drop keyword, remove default drop stuff
		e.drop = 0
	}

	return e, nil
}
