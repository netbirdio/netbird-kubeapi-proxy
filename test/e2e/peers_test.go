// SPDX-License-Identifier: AGPL-3.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// readerGroup is the NetBird group examples/read-only.yaml binds to the
	// cluster-reader ClusterRole. The proxy impersonates a peer's groups by
	// name, so the same name on both sides is the whole integration.
	readerGroup = "kubernetes-read"

	readerName   = "reader"
	outsiderName = "outsider"
)

// outsidePeer is a NetBird peer outside the cluster, standing in for a user's
// device, and its ID in management.
type outsidePeer struct {
	client *harness.Client
	id     string
}

// startOutsidePeers starts reader, in readerGroup, and outsider, in no group of
// its own, and waits until both reach the proxy. The account's default policy
// lets every peer reach every other, so the proxy decides what each may do.
func (e *environment) startOutsidePeers(ctx context.Context) error {
	group, err := e.nb.Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: readerGroup})
	if err != nil {
		return fmt.Errorf("create group %s: %w", readerGroup, err)
	}
	e.reader, err = e.startOutsidePeer(ctx, readerName, []string{group.Id})
	if err != nil {
		return err
	}
	e.outsider, err = e.startOutsidePeer(ctx, outsiderName, []string{})
	if err != nil {
		return err
	}
	for _, peer := range []*outsidePeer{e.reader, e.outsider} {
		if err := e.waitReachesProxy(ctx, peer); err != nil {
			return err
		}
	}
	return nil
}

func (e *environment) startOutsidePeer(ctx context.Context, name string, groups []string) (*outsidePeer, error) {
	key, err := e.nb.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + name,
		Type:       "reusable",
		ExpiresIn:  int((24 * time.Hour).Seconds()),
		AutoGroups: groups,
	})
	if err != nil {
		return nil, fmt.Errorf("create the setup key for %s: %w", name, err)
	}
	client, err := harness.StartClient(ctx, e.srv, key.Key, harness.WithClientName(name))
	if err != nil {
		return nil, fmt.Errorf("start the %s peer: %w", name, err)
	}
	peer := &outsidePeer{client: client}
	if err := client.WaitConnected(ctx, 3*time.Minute); err != nil {
		return peer, fmt.Errorf("connect the %s peer: %w\n%s", name, err, tail(client.Logs(ctx)))
	}

	peers, err := e.nb.Peers.List(ctx)
	if err != nil {
		return peer, fmt.Errorf("list peers: %w", err)
	}
	for _, p := range peers {
		if p.Hostname == name {
			peer.id = p.Id
			return peer, nil
		}
	}
	return peer, fmt.Errorf("management lists no peer with hostname %s", name)
}

// waitReachesProxy waits until a peer gets an answer from the proxy at all. A
// peer that has just connected to management can take a while longer to set up
// its tunnel to the proxy.
func (e *environment) waitReachesProxy(ctx context.Context, peer *outsidePeer) error {
	var last error
	err := wait.PollUntilContextTimeout(ctx, 3*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, last = e.get(ctx, peer, "/version")
		return last == nil, nil
	})
	if err != nil {
		return fmt.Errorf("%s never reached the proxy at %s: %w (last: %w)", peer.client.Hostname(), e.proxyPeer.Ip, err, last)
	}
	return nil
}

// response is what a peer got back from the proxy. body is empty on an error
// status, which wget does not save.
type response struct {
	status int
	body   string
}

// requestScript fetches $1 with the remaining arguments passed to wget, and
// prints the first status line wget saw, a separator, then the body. wget
// follows redirects, so the first status is the one that shows a redirect. The
// headers and the body go through files: piping wget into a reader that stops
// early would kill it before it writes the body.
const requestScript = `url=$1; shift
d=$(mktemp -d)
wget -S -q --no-check-certificate -T 10 -O "$d/body" "$@" "$url" 2>"$d/headers"
grep -m1 -o 'HTTP/[0-9.]* [0-9]*' "$d/headers"
echo "` + bodySeparator + `"
cat "$d/body" 2>/dev/null; rm -rf "$d"`

const bodySeparator = "--- body ---"

var statusLine = regexp.MustCompile(`HTTP/[0-9.]+ ([0-9]{3})`)

// get sends a GET through the proxy from a peer, with extra headers given as
// "Name: value".
func (e *environment) get(ctx context.Context, peer *outsidePeer, path string, headers ...string) (response, error) {
	return e.request(ctx, peer, path, "", headers...)
}

// post sends a JSON POST through the proxy from a peer.
func (e *environment) post(ctx context.Context, peer *outsidePeer, path, body string, headers ...string) (response, error) {
	return e.request(ctx, peer, path, body, append(headers, "Content-Type: application/json")...)
}

// request runs wget inside the peer's container, so it takes whatever route the
// peer's NetBird client set up to the proxy. An error means no HTTP answer came
// back; an HTTP error status is a response.
func (e *environment) request(ctx context.Context, peer *outsidePeer, path, body string, headers ...string) (response, error) {
	url := "https://" + e.proxyPeer.Ip + path
	cmd := []string{"sh", "-c", requestScript, "sh", url}
	for _, h := range headers {
		cmd = append(cmd, "--header", h)
	}
	if body != "" {
		cmd = append(cmd, "--post-data", body)
	}

	_, out, err := peer.client.Exec(ctx, cmd...)
	if err != nil {
		return response{}, err
	}
	return parseResponse(out)
}

func parseResponse(out string) (response, error) {
	head, body, ok := strings.Cut(out, bodySeparator+"\n")
	if !ok {
		return response{}, fmt.Errorf("unexpected wget output: %q", out)
	}
	m := statusLine.FindStringSubmatch(head)
	if m == nil {
		return response{}, fmt.Errorf("no HTTP response: %q", head)
	}
	status, err := strconv.Atoi(m[1])
	if err != nil {
		return response{}, err
	}
	return response{status: status, body: body}, nil
}
