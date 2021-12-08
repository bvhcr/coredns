package onlyone

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type typeMap map[uint16]bool

type onlyone struct {
	Next  plugin.Handler
	zones []string
	types typeMap
	pick  func(int) int
}

func (o *onlyone) Name() string { return "onlyone" }

// ServeDNS implements the plugin.Handle interface.
func (o *onlyone) ServeDNS(ctx context.Context, w dns.ResponseWriter,
	r *dns.Msg) (int, error) {
	// The request struct is a convenience struct.
	state := request.Request{W: w, Req: r}
	log.Infof("user req: %d\n", r.MsgHdr.Id)

	// If the zone does not match one of ours, just pass it on.
	if plugin.Zones(o.zones).Matches(state.Name()) == "" {
		return plugin.NextOrFailure(o.Name(), o.Next, ctx, w, r)
	}

	// The zone matches ours, so use a nonwriter to capture the response.
	nw := nonwriter.New(w)

	// Call all the next plugin in the chain.
	rcode, err := plugin.NextOrFailure(o.Name(), o.Next, ctx, nw, r)
	if err != nil {
		// Simply return if there was an error.
		return rcode, err
	}
	log.Infof("user resp: %+v\n", nw.Msg)

	// Now we know that a successful response was received from a plugin
	// that appears later in the chain. Next is to examine that response
	// and trim out extra records, then write it to the client.
	// w.WriteMsg(o.trimRecords(nw.Msg))
	w.WriteMsg(o.trimPhantomRecords(&state, nw.Msg))
	return rcode, err
}

func getSuccessReply(r *request.Request) *dns.Msg {
	/*
		;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13719
		;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
	*/
	var m = new(dns.Msg)
	m = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 r.Req.Id,
			Opcode:             dns.OpcodeQuery,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess, // dns.RcodeNameError,
			Response:           true,
		},
		Question: []dns.Question{
			{
				Name:   r.Name(),
				Qtype:  r.QType(),
				Qclass: r.QClass(),
			},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:     r.Name(),
					Rrtype:   dns.TypeA,
					Class:    dns.ClassINET,
					Ttl:      600,
					Rdlength: net.IPv4len,
				},
				A: net.IPv4(34, 206, 39, 153),
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:     r.Name(),
					Rrtype:   dns.TypeA,
					Class:    dns.ClassINET,
					Ttl:      0,
					Rdlength: net.IPv4len,
				},
				A: net.IPv4(34, 206, 39, 154),
			},
		},
	}
	return m
}

/*
// SetReply creates a reply message from a request message.
func (dns *Msg) SetReply(request *Msg) *Msg {
	dns.Id = request.Id
	dns.Response = true
	dns.Opcode = request.Opcode
	if dns.Opcode == OpcodeQuery {
		dns.RecursionDesired = request.RecursionDesired // Copy rd bit
		dns.CheckingDisabled = request.CheckingDisabled // Copy cd bit
	}
	dns.Rcode = RcodeSuccess
	if len(request.Question) > 0 {
		dns.Question = make([]Question, 1)
		dns.Question[0] = request.Question[0]
	}
	return dns
}
*/

func getServerFailureReply(r *request.Request) *dns.Msg {
	/*
		;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 64843
		;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

		;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 39641
		;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	*/
	var m = new(dns.Msg)
	m = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 r.Req.Id,
			Opcode:             dns.OpcodeQuery,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeRefused, // dns.RcodeServerFailure, RcodeRefused, RcodeSuccess
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

func (o *onlyone) trimPhantomRecords(r *request.Request, m *dns.Msg) *dns.Msg {
	log.Info("update After!")
	log.Info("update Remote stat: %s", m.Rcode)
	m = getSuccessReply(r)
	return m
}

func (o *onlyone) trimRecords(m *dns.Msg) *dns.Msg {
	// The trimming behavior is relatively expensive, so if there is one
	// or fewer answers, we know it doesn't apply so just return.
	if len(m.Answer) <= 1 {
		return m
	}

	// Allocate an array to hold answers to keep.
	keep := make([]bool, len(m.Answer))

	// Allocate a map to correlate each subject type to a list of indexes.
	indexes := make(map[uint16][]int, len(o.types)/2)

	// Loop through the answers, either deciding to keep it, or putting
	// it in a provisional list of indexes for a subject type.
	for i, a := range m.Answer {
		h := a.Header()
		if _, ok := o.types[h.Rrtype]; ok {
			// this type is subject to this plugin, so stash
			// away the index of this record for later.
			provisional, _ := indexes[h.Rrtype]
			indexes[h.Rrtype] = append(provisional, i)
		} else {
			// not subject to this plugin, so we keep it.
			keep[i] = true
		}
	}

	// Now we loop through each type with multiple records and pick one.
	for _, provisional := range indexes {
		keep[provisional[o.pick(len(provisional))]] = true
	}

	// Now copy the ones we want to keep into a new Answer list.
	var newAnswer []dns.RR
	for i, a := range m.Answer {
		if keep[i] {
			newAnswer = append(newAnswer, a)
		}
	}
	m.Answer = newAnswer
	return m
}
