package routealias

import (
	"context"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("routealias")

// Example is an example plugin to show how to write a plugin.
type RouteAlias struct {
	Next            plugin.Handler
	router          OPNsenseAPI
	whitelist       APBList
	cache           Cache
	alias_name      string
	wait_for_record bool
	kill_state      bool
}

func NewRouteAlias(next plugin.Handler, config Config) *RouteAlias {
	ra := RouteAlias{
		Next:            next,
		router:          NewOPNsenseAPIClient(config.api_key, config.api_secret, config.host, config.skip_verify),
		whitelist:       NewABPList(config.whitelist_path),
		cache:           NewCache(),
		wait_for_record: config.wait_for_record,
		alias_name:      config.alias_name,
		kill_state:      config.kill_state,
	}
	if config.flush_on_start {
		err := ra.router.FlushAlias(config.alias_name)
		if err != nil {
			log.Errorf("failed to flush alias: %s: %s", config.alias_name, err.Error())
		}
	}
	return &ra
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (e *RouteAlias) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// This function could be simpler. I.e. just fmt.Println("example") here, but we want to show
	// a slightly more complex example as to make this more interesting.
	// Here we wrap the dns.ResponseWriter in a new ResponseWriter and call the next plugin, when the
	// answer comes back, it will print "example".

	// Wrap.
	pw := ResponseWriter{r: e, ResponseWriter: w}

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, &pw, r)
}

// Name implements the Handler interface.
func (e *RouteAlias) Name() string { return "routealias" }

// ResponsePrinter wrap a dns.ResponseWriter and will write example to standard output when WriteMsg is called.
type ResponseWriter struct {
	dns.ResponseWriter
	r *RouteAlias
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and prints "example" to standard output.
func (r *ResponseWriter) WriteMsg(res *dns.Msg) error {
	r.AddIfRequired(res.Answer)
	return r.ResponseWriter.WriteMsg(res)
}

func (w *ResponseWriter) AddIfRequired(answers []dns.RR) {
	for _, answer := range answers {
		ip := ""
		if answer.Header().Rrtype == dns.TypeA {
			ip = answer.(*dns.A).A.String()
		} else if answer.Header().Rrtype == dns.TypeAAAA {
			ip = answer.(*dns.AAAA).AAAA.String()
		} else {
			// ignore requests other than A/AAAA
			continue
		}

		if !w.r.cache.Exists(ip) && w.r.whitelist.Match(answer.Header().Name) {
			addIP := func() {
				err := w.r.router.AddAliasIP(w.r.alias_name, ip)
				if err != nil {
					log.Errorf("failed to add ip: %s to opnsense alias: %s: %s", ip, w.r.alias_name, err.Error())
					return
				}
				w.r.cache.Add(ip)

				if w.r.kill_state {
					err = w.r.router.KillStates(ip)
					if err != nil {
						log.Errorf("failed to kill state for ip: %s: %s", ip, err.Error())
					}
				}
			}

			if w.r.wait_for_record {
				go addIP()
			} else {
				addIP()
			}
		}
	}
}
