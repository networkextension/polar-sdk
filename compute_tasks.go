package sdk

// compute_tasks.go — SDK wrappers for module-originated compute tasks
// (polar-task P2). A plugin submits on-device compute work to dock's queue; the
// fleet runs it and (P3) calls back. Tasks default to `hold` until released.
// All calls are scoped server-side to the calling plugin (requester_module).
//
//   SubmitComputeTask   POST   /internal/v1/compute-tasks
//   ListMyComputeTasks  GET    /internal/v1/compute-tasks
//   GetComputeTask      GET    /internal/v1/compute-tasks/:id
//   ReleaseComputeTask  POST   /internal/v1/compute-tasks/:id/release

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SubmitComputeTaskRequest originates a compute task. WorkspaceID + Skill are
// required; the task is claimed by an agent in that workspace. Input is the
// skill's raw JSON (e.g. {"asset_id":N} for vision.ocr). AutoStart skips the
// default `hold`. CallbackPath (+ RequesterRef) are echoed in the P3 callback.
type SubmitComputeTaskRequest struct {
	WorkspaceID  string          `json:"workspace_id"`
	Skill        string          `json:"skill"`
	Input        json.RawMessage `json:"input,omitempty"`
	Constraints  json.RawMessage `json:"constraints,omitempty"`
	Priority     int             `json:"priority,omitempty"`
	CallbackPath string          `json:"callback_path,omitempty"`
	RequesterRef string          `json:"requester_ref,omitempty"`
	ActingUserID string          `json:"acting_user_id,omitempty"`
	AutoStart    bool            `json:"auto_start,omitempty"`
}

// ComputeTask mirrors dock's AgentTask (the fields a requester cares about).
type ComputeTask struct {
	ID           string          `json:"id"`
	WorkspaceID  string          `json:"workspace_id"`
	Skill        string          `json:"skill"`
	Input        json.RawMessage `json:"input,omitempty"`
	Priority     int             `json:"priority"`
	Status       string          `json:"status"`
	AgentID      string          `json:"agent_id,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        string          `json:"error,omitempty"`
	RequesterRef string          `json:"requester_ref,omitempty"`
	CallbackPath string          `json:"callback_path,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	ClaimedAt    *time.Time      `json:"claimed_at,omitempty"`
	ReleasedAt   *time.Time      `json:"released_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// ComputeTaskArtifact is a file output (stored in polar-assets).
type ComputeTaskArtifact struct {
	Kind        string `json:"kind"`
	AssetID     int64  `json:"asset_id"`
	Mime        string `json:"mime"`
	Bytes       int64  `json:"bytes"`
	DownloadURL string `json:"download_url,omitempty"`
}

// ComputeTaskWithArtifacts is the GET /:id response.
type ComputeTaskWithArtifacts struct {
	Task      ComputeTask           `json:"task"`
	Artifacts []ComputeTaskArtifact `json:"artifacts"`
}

// ListComputeTasksFilter narrows ListMyComputeTasks. All optional.
type ListComputeTasksFilter struct {
	Status       string // queued|hold|running|done|failed|cancelled
	RequesterRef string
	Limit        int
}

// SubmitComputeTask queues an on-device compute task (default hold).
func (c *Client) SubmitComputeTask(req SubmitComputeTaskRequest) (*ComputeTask, error) {
	if req.WorkspaceID == "" || req.Skill == "" {
		return nil, errInvalid("SubmitComputeTask: workspace_id and skill required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/compute-tasks", req)
	if err != nil {
		return nil, err
	}
	var out ComputeTask
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListMyComputeTasks lists this module's own tasks (newest first).
func (c *Client) ListMyComputeTasks(filter ListComputeTasksFilter) ([]ComputeTask, error) {
	q := url.Values{}
	if filter.Status != "" {
		q.Set("status", filter.Status)
	}
	if filter.RequesterRef != "" {
		q.Set("requester_ref", filter.RequesterRef)
	}
	if filter.Limit > 0 {
		q.Set("limit", strconv.Itoa(filter.Limit))
	}
	path := "/internal/v1/compute-tasks"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tasks []ComputeTask `json:"tasks"`
	}
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return out.Tasks, nil
}

// GetComputeTask fetches one of this module's tasks + its artifacts (download URLs).
func (c *Client) GetComputeTask(id string) (*ComputeTaskWithArtifacts, error) {
	if id == "" {
		return nil, errInvalid("GetComputeTask: id required")
	}
	resp, err := c.Do(http.MethodGet, "/internal/v1/compute-tasks/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var out ComputeTaskWithArtifacts
	if err := readJSON(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReleaseComputeTask flips a held task to queued (claimable by the fleet).
func (c *Client) ReleaseComputeTask(id string) error {
	if id == "" {
		return errInvalid("ReleaseComputeTask: id required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/compute-tasks/"+url.PathEscape(id)+"/release", nil)
	if err != nil {
		return err
	}
	return readJSON(resp, nil)
}
