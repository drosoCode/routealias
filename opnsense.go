package routealias

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type OPNsenseAPI struct {
	client     http.Client
	authHeader string
	baseUrl    string
}

type AliasUUIDResponse struct {
	UUID string `json:"uuid"`
}

func NewOPNsenseAPIClient(api_key string, api_secret string, url string, skip_verify bool) OPNsenseAPI {
	a := OPNsenseAPI{
		client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: skip_verify},
			},
		},
		authHeader: fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", api_key, api_secret)))),
		baseUrl:    url,
	}
	return a
}

func (a *OPNsenseAPI) AddAliasIP(alias_name string, ip string) error {
	form := url.Values{}
	form.Add("address", ip)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/firewall/alias_util/add/%s", a.baseUrl, alias_name), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", a.authHeader)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("status code: %d", resp.StatusCode)
	}
	return nil
}

func (a *OPNsenseAPI) FlushAlias(alias_name string) error {
	// get alias uuid
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/firewall/alias/get_alias_u_u_i_d/%s", a.baseUrl, alias_name), nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Add("Authorization", a.authHeader)
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code: %d", resp.StatusCode)
	}
	var uuidResp AliasUUIDResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read data: %s", err.Error())
	}
	err = json.Unmarshal(body, &uuidResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %s", err.Error())
	}

	// set alias content to empty
	req, err = http.NewRequest("POST", fmt.Sprintf("%s/api/firewall/alias/set_item/%s", a.baseUrl, uuidResp.UUID), bytes.NewBuffer([]byte("{\"alias\":{\"content\": \"\"}}")))
	if err != nil {
		return fmt.Errorf("creating request 2: %w", err)
	}
	req.Header.Add("Authorization", a.authHeader)
	req.Header.Add("Content-Type", "application/json")
	resp, err = a.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing request 2: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code 2: %d", resp.StatusCode)
	}

	return nil
}
