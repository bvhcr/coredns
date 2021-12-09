// Package erratic implements a plugin that returns erratic answers (delayed, dropped).
package eccentric

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const (
	ttlMax = 1<<32 - 1
	ttlMin = 0
)

/*
acl section
*/

// ACL enforces access control policies on DNS queries.
type ACL struct {
	// Next  plugin.Handler
	Rules []rule
}

// rule defines a list of Zones and some ACL policies which will be
// enforced on them.
type rule struct {
	zones    []string
	policies []policy
}

// action defines the action against queries.
type action int

// policy defines the ACL policy for DNS queries.
// A policy performs the specified action (block/allow) on all DNS queries
// matched by source IP or QTYPE.
type policy struct {
	action action
	qtypes map[uint16]struct{}
	// filter *iptree.Tree
}

const (
	// actionAllow allows authorized queries to recurse.
	permit       = iota // 0
	permitAndlog        // 1
	// actionBlock blocks unauthorized queries towards protected DNS zones.
	forbid       // 2
	forbidAndlog // 3
	// actionFilter returns empty sets for queries towards protected DNS zones.
	filter
	filterAndlog
	actionNone
	phantomAndLog
	limitAndlog
)

/*
err section
*/
type typeMap map[uint16]bool

// Erratic is a plugin that returns erratic responses to each client.
type Eccentric struct {
	q        uint64 // counter of queries
	drop     uint64
	delay    uint64
	truncate uint64

	duration time.Duration
	large    bool // undocumented feature; return large responses for A request (>512B, to test compression).

	Next  plugin.Handler
	zones []string
	types typeMap
	pick  func(int) int
	acl   *ACL
}

// matchWithPolicies matches the DNS query with a list of ACL polices and returns suitable
// action against the query.
func matchWithPolicies(policies []policy, w dns.ResponseWriter, r *dns.Msg) action {
	state := request.Request{W: w, Req: r}

	// ip := net.ParseIP(state.IP())
	qtype := state.QType()
	for _, policy := range policies {
		log.Info("逐个判断策略,", policy)
		// dns.TypeNone matches all query types.
		_, matchAll := policy.qtypes[dns.TypeNone]
		_, match := policy.qtypes[qtype]
		if !matchAll && !match {
			continue
		}

		/*
			禁止ip匹配规则
			_, contained := policy.filter.GetByIP(ip)
			if !contained {
				continue
			}
		*/

		// matched.
		return policy.action
	}
	return actionNone
}

// matchWithPolicies matches the DNS query with a list of ACL polices and returns suitable
// action against the query.
func matchWithPoliciesV2(policies []policy, w dns.ResponseWriter, r *dns.Msg) action {
	state := request.Request{W: w, Req: r}

	// ip := net.ParseIP(state.IP())
	qtype := state.QType()
	for _, policy := range policies {
		log.Info("逐个判断策略,", policy)
		// dns.TypeNone matches all query types.
		_, matchAll := policy.qtypes[dns.TypeNone]
		_, match := policy.qtypes[qtype]
		if !matchAll && !match {
			continue
		}

		/*
			禁止ip匹配规则
			_, contained := policy.filter.GetByIP(ip)
			if !contained {
				continue
			}
		*/

		// matched.
		return policy.action
	}
	return actionNone
}

func (e *Eccentric) mistake(w dns.ResponseWriter, r *dns.Msg) action {
	state := request.Request{W: w, Req: r}
	for _, rule := range e.acl.Rules {
		// check zone.
		zone := plugin.Zones(rule.zones).Matches(state.Name())
		if zone == "" {
			continue
		}

		action := matchWithPolicies(rule.policies, w, r)
		return action
		/*
			switch action {
			case forbidAndlog:
				{
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					w.WriteMsg(m)
					return dns.RcodeSuccess, nil
				}
			case permitAndlog:
				{
					break RulesCheckLoop
				}
			case filterAndlog:
				{
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeSuccess)
					w.WriteMsg(m)
					return dns.RcodeSuccess, nil
				}
			case phantomAndLog:
				{
				}
			}
		*/
	}
	return permitAndlog
}

func composeHdrWithCtx(r *request.Request, rcode int) *dns.Msg {
	// var m = new(dns.Msg)
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 r.Req.Id,
			Opcode:             dns.OpcodeQuery,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              rcode, // dns.RcodeSuccess
			Response:           true,
		},
		Question: []dns.Question{
			{
				Name:   r.Name(),
				Qtype:  r.QType(),
				Qclass: r.QClass(),
			},
		},
	}
	return m
}

// ServeDNS implements the plugin.Handler interface.
func (e *Eccentric) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	drop := false
	delay := false
	trunc := false

	queryNr := atomic.LoadUint64(&e.q)
	atomic.AddUint64(&e.q, 1)

	if e.drop > 0 && queryNr%e.drop == 0 {
		drop = true
	}
	if e.delay > 0 && queryNr%e.delay == 0 {
		delay = true
	}
	if e.truncate > 0 && queryNr&e.truncate == 0 {
		trunc = true
	}

	var m = new(dns.Msg)
	// m := new(dns.Msg)
	// m.SetReply(r)
	m.Authoritative = true
	if trunc {
		m.Truncated = true
	}
	log.Info("==>", state.Name())
	log.Infof("%+v \n", e.acl.Rules)
	log.Infof("%#v \n", e.acl.Rules)

	/*
		RulesCheckLoop:
			for _, rule := range e.acl.Rules {
				// check zone.
				zone := plugin.Zones(rule.zones).Matches(state.Name())
				if zone == "" {
					continue
				}

				action := matchWithPolicies(rule.policies, w, r)
				switch action {
				case forbidAndlog:
					{
						m := new(dns.Msg)
						m.SetRcode(r, dns.RcodeRefused)
						w.WriteMsg(m)
						return dns.RcodeSuccess, nil
					}
				case permitAndlog:
					{
						break RulesCheckLoop
					}
				case filterAndlog:
					{
						m := new(dns.Msg)
						m.SetRcode(r, dns.RcodeSuccess)
						w.WriteMsg(m)
						return dns.RcodeSuccess, nil
					}
				case phantomAndLog:
					{
					}
				}
			}
	*/

	/*
		// If the zone does not match one of ours, just pass it on.
		if plugin.Zones(e.zones).Matches(state.Name()) == "" {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}

		// The zone matches ours, so use a nonwriter to capture the response.
		nw := nonwriter.New(w)

		// Call all the next plugin in the chain.
		rcode, err := plugin.NextOrFailure(e.Name(), e.Next, ctx, nw, r)
		if err != nil {
			// Simply return if there was an error.
			return rcode, err
		}
	*/

	// Action
	action := e.mistake(w, r)
	log.Info("操作:", action)

	switch action {
	case forbidAndlog:
		{
			m = composeHdrWithCtx(&state, dns.RcodeRefused)
			/*
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return dns.RcodeSuccess, nil
			*/
		}
	case phantomAndLog:
		{
			m = composeHdrWithCtx(&state, dns.RcodeSuccess)
			m.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:     state.Name(),
						Rrtype:   dns.TypeA,
						Class:    dns.ClassINET,
						Ttl:      uint32(ttlMax),
						Rdlength: net.IPv4len,
					},
					A: net.IPv4(34, 206, 39, 153),
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name:     state.Name(),
						Rrtype:   dns.TypeA,
						Class:    dns.ClassINET,
						Ttl:      uint32(ttlMin),
						Rdlength: net.IPv4len,
					},
					A: net.IPv4(34, 206, 39, 154),
				},
			}
		}
	}

	/*
		// If the zone does not match one of ours, just pass it on.
		if plugin.Zones(e.zones).Matches(state.Name()) == "" {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}

		// The zone matches ours, so use a nonwriter to capture the response.
		nw := nonwriter.New(w)

		// Call all the next plugin in the chain.
		rcode, err := plugin.NextOrFailure(e.Name(), e.Next, ctx, nw, r)
		if err != nil {
			// Simply return if there was an error.
			return rcode, err
		}
	*/

	// Now we know that a successful response was received from a plugin
	// that appears later in the chain. Next is to examine that response
	// and trim out extra records, then write it to the client.
	// w.WriteMsg(o.trimRecords(nw.Msg))

	/*
		w.WriteMsg(e.trimPhantomRecords(&state, nw.Msg))
		return rcode, err
		1. action
			- phantom 幻影,假IPv4和IPv6
			- limit 限制记录数量,onlyone
	*/

	// small dance to copy rrA or rrAAAA into a non-pointer var that allows us to overwrite the ownername
	// in a non-racy way.
	// 从这里开始不判断请求类型的逻辑
	/*
		switch state.QType() {
		case dns.TypeA:
			rr := *(rrA.(*dns.A))
			rr.Header().Name = state.QName()
			m.Answer = append(m.Answer, &rr)
			if e.large {
				for i := 0; i < 29; i++ {
					m.Answer = append(m.Answer, &rr)
				}
			}
			log.Info("--------> query ipv4.")
		case dns.TypeAAAA:
			rr := *(rrAAAA.(*dns.AAAA))
			rr.Header().Name = state.QName()
			m.Answer = append(m.Answer, &rr)
		case dns.TypeAXFR:
			if drop {
				return 0, nil
			}
			if delay {
				time.Sleep(e.duration)
			}

			xfr(state, trunc)
			return 0, nil

		default:
			if drop {
				return 0, nil
			}
			if delay {
				time.Sleep(e.duration)
			}
			// coredns will return error.
			log.Info("==>", state.Name(), "兜底逻辑")
			return dns.RcodeNotImplemented, nil // dns.RcodeServerFailure,
		}
	*/

	if drop {
		return 0, nil
	}

	if delay {
		time.Sleep(e.duration)
	}

	w.WriteMsg(m)

	return 0, nil
}

// Name implements the Handler interface.
func (e *Eccentric) Name() string { return pluginName } //  { return "erratic" }

var (
	rrA, _    = dns.NewRR(". IN 0 A 192.0.2.53")
	rrAAAA, _ = dns.NewRR(". IN 0 AAAA 2001:DB8::53")
)
