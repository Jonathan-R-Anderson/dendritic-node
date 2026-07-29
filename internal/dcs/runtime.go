package dcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// The Docker Engine API is spoken directly over its unix socket with net/http
// rather than through github.com/docker/docker. That client pulls in an
// enormous dependency tree for what is, here, four endpoints -- and this
// binary cross-compiles to six targets with CGO_ENABLED=0, where a smaller
// dependency surface is worth more than convenience wrappers.

type DockerClient struct {
	http     *http.Client
	endpoint string
	apiBase  string
}

func NewDockerClient(endpoint string) (*DockerClient, error) {
	socket := strings.TrimPrefix(endpoint, "unix://")
	if socket == "" || !strings.HasPrefix(endpoint, "unix://") {
		return nil, fmt.Errorf("dcs: only unix:// docker endpoints are supported, got %q", endpoint)
	}
	return &DockerClient{
		endpoint: endpoint,
		apiBase:  "http://docker",
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}, nil
}

func (c *DockerClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dcs: docker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&msg)
		return fmt.Errorf("dcs: docker %s %s: HTTP %d: %s",
			method, path, resp.StatusCode, msg.Message)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *DockerClient) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_ping", nil, nil)
}

// ContainerSpec is what a deployment asks for. It is deliberately NOT the
// Docker create body: everything dangerous in that body is absent here, so a
// deployer has no field in which to request it.
type ContainerSpec struct {
	Name             string
	Image            string // digest-pinned reference
	Cmd              []string
	Env              []string
	Labels           map[string]string
	MemoryLimitBytes int64
	NanoCPUs         int64
	PidsLimit        int64
	ReadOnlyRootfs   bool
	TmpfsMounts      map[string]string
	// Lab marks a deliberately vulnerable workload. It tightens the profile
	// further; it never loosens it.
	Lab bool
}

// HostConfig fragments we always set, and the ones we never accept, live here
// so the profile is one auditable block rather than scattered assignments.
type dockerCreateBody struct {
	Image           string            `json:"Image"`
	Cmd             []string          `json:"Cmd,omitempty"`
	Env             []string          `json:"Env,omitempty"`
	Labels          map[string]string `json:"Labels,omitempty"`
	NetworkDisabled bool              `json:"NetworkDisabled"`
	HostConfig      dockerHostConfig  `json:"HostConfig"`
}

type dockerHostConfig struct {
	Memory         int64             `json:"Memory,omitempty"`
	NanoCpus       int64             `json:"NanoCpus,omitempty"`
	PidsLimit      *int64            `json:"PidsLimit,omitempty"`
	CapDrop        []string          `json:"CapDrop"`
	SecurityOpt    []string          `json:"SecurityOpt"`
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	NetworkMode    string            `json:"NetworkMode"`
	Privileged     bool              `json:"Privileged"`
	AutoRemove     bool              `json:"AutoRemove"`
	RestartPolicy  struct {
		Name string `json:"Name"`
	} `json:"RestartPolicy"`
}

// hardened builds the create body. This is the only place a container is
// configured, which is what makes the guarantees checkable: there is no second
// path where Privileged could become true.
func hardened(spec ContainerSpec) dockerCreateBody {
	pids := spec.PidsLimit
	if pids <= 0 {
		pids = 256
	}
	tmpfs := spec.TmpfsMounts
	if tmpfs == nil {
		tmpfs = map[string]string{}
	}
	// A read-only rootfs with nowhere to write breaks most images, so /tmp is
	// always provided as a small tmpfs rather than leaving the operator to
	// discover the failure.
	if _, ok := tmpfs["/tmp"]; !ok {
		tmpfs["/tmp"] = "rw,noexec,nosuid,size=64m"
	}

	body := dockerCreateBody{
		Image:  spec.Image,
		Cmd:    spec.Cmd,
		Env:    spec.Env,
		Labels: spec.Labels,
		// Docker's own networking is disabled entirely. The container reaches
		// the network only through the I2P destination the agent attaches, so
		// there is no bridge, no port binding, and no route to the host LAN.
		NetworkDisabled: true,
		HostConfig: dockerHostConfig{
			Memory:    spec.MemoryLimitBytes,
			NanoCpus:  spec.NanoCPUs,
			PidsLimit: &pids,
			CapDrop:   []string{"ALL"},
			SecurityOpt: []string{
				"no-new-privileges:true",
			},
			ReadonlyRootfs: true,
			Tmpfs:          tmpfs,
			NetworkMode:    "none",
			Privileged:     false,
		},
	}
	// A lab container never restarts: a vulnerable service that resurrects
	// itself outlives the researcher's attention, which is exactly what the
	// runtime ceiling exists to prevent.
	if spec.Lab {
		body.HostConfig.RestartPolicy.Name = "no"
		body.HostConfig.AutoRemove = false
	} else {
		body.HostConfig.RestartPolicy.Name = "no"
	}
	return body
}

var ErrEmptyImage = errors.New("dcs: container spec has no image")

// Create makes the container. It never starts it: the agent attaches the I2P
// destination between create and start, so a container cannot run for even an
// instant before its network identity exists.
func (c *DockerClient) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	if strings.TrimSpace(spec.Image) == "" {
		return "", ErrEmptyImage
	}
	body := hardened(spec)
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	path := "/containers/create"
	if spec.Name != "" {
		path += "?name=" + spec.Name
	}
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (c *DockerClient) Start(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
}

func (c *DockerClient) Stop(ctx context.Context, id string, grace int) error {
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/containers/%s/stop?t=%d", id, grace), nil, nil)
}

func (c *DockerClient) Remove(ctx context.Context, id string, force bool) error {
	path := "/containers/" + id + "?v=1"
	if force {
		path += "&force=1"
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// InspectState is the redacted projection. The raw Docker inspect response
// carries host paths, the hostname and network details; returning it wholesale
// would leak the worker's environment to whoever deployed the container, and
// would leak any NEW field a future Docker version adds. Whitelist, never
// blacklist.
type InspectState struct {
	ID        string `json:"id"`
	Image     string `json:"image"`
	Running   bool   `json:"running"`
	Paused    bool   `json:"paused"`
	Restarts  int    `json:"restarts"`
	OOMKilled bool   `json:"oom_killed"`
	ExitCode  int    `json:"exit_code"`
	StartedAt string `json:"started_at"`
	Health    string `json:"health,omitempty"`
}

// ContainerPID returns the container's main process PID, needed to enter its
// network namespace (netns_linux.go). A PID of 0 means the container is not
// running, so there is no namespace to join.
func (c *DockerClient) ContainerPID(ctx context.Context, id string) (int, error) {
	var raw struct {
		State struct {
			Pid     int  `json:"Pid"`
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &raw); err != nil {
		return 0, err
	}
	if !raw.State.Running || raw.State.Pid <= 0 {
		return 0, fmt.Errorf("dcs: container %s is not running", id)
	}
	return raw.State.Pid, nil
}

func (c *DockerClient) Inspect(ctx context.Context, id string) (InspectState, error) {
	var raw struct {
		ID    string `json:"Id"`
		Image string `json:"Image"`
		State struct {
			Running    bool   `json:"Running"`
			Paused     bool   `json:"Paused"`
			Restarting bool   `json:"Restarting"`
			OOMKilled  bool   `json:"OOMKilled"`
			ExitCode   int    `json:"ExitCode"`
			StartedAt  string `json:"StartedAt"`
			Health     *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		RestartCount int `json:"RestartCount"`
	}
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &raw); err != nil {
		return InspectState{}, err
	}
	out := InspectState{
		ID: raw.ID, Image: raw.Image,
		Running: raw.State.Running, Paused: raw.State.Paused,
		Restarts: raw.RestartCount, OOMKilled: raw.State.OOMKilled,
		ExitCode: raw.State.ExitCode, StartedAt: raw.State.StartedAt,
	}
	if raw.State.Health != nil {
		out.Health = raw.State.Health.Status
	}
	return out, nil
}
