package routealias

import (
	"bufio"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type APBList struct {
	list map[string]bool
}

func NewABPList(filePath string) APBList {
	list_raw_data, err := os.Open(filePath)
	if err != nil {
		log.Errorf("could not read blocklist file: %s", filePath)
		return APBList{}
	}
	defer list_raw_data.Close()

	newList := make(map[string]bool)
	scanner := bufio.NewScanner(list_raw_data)
	for scanner.Scan() {
		hostLine := scanner.Text()
		if strings.HasPrefix(hostLine, "!") || hostLine == "" {
			continue
		}
		if !strings.HasPrefix(hostLine, "||") || !strings.HasSuffix(hostLine, "^") {
			log.Warningf("line \"%s\" does not match parseable ABP syntax subset", hostLine)
			continue
		}
		hostLine = strings.TrimPrefix(hostLine, "||")
		hostLine = strings.TrimSuffix(hostLine, "^")
		newList[dns.Fqdn(hostLine)] = true
	}

	return APBList{list: newList}
}

func (d *APBList) Match(domain string) bool {
	// We will check every subdomain of the given domain against the blocklist. i.e. if example.com
	// is blocked, then every subdomain of that (subdomain.example.com, sub1.sub2.example.com) is
	// blocked. However, example.com.org is not blocked.
	comps := strings.Split(domain, ".")
	current := comps[len(comps)-1]
	for i := len(comps) - 2; i >= 0; i-- {
		newCurrent := strings.Join([]string{
			comps[i],
			current,
		}, ".")

		if d.list[newCurrent] {
			return true
		}
		current = newCurrent
	}
	return false
}
