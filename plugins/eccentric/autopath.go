package eccentric

import "github.com/coredns/coredns/request"

// AutoPath implements the AutoPathFunc call from the autopath plugin.
func (e *Eccentric) AutoPath(state request.Request) []string {
	return []string{"a.example.org.", "b.example.org.", ""}
}
