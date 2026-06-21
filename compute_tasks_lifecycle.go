package sdk

// compute_tasks_lifecycle.go — P2b lifecycle wrappers + P3 callback verify.
//
//   PauseComputeTask    POST /internal/v1/compute-tasks/:id/pause
//   ResumeComputeTask   POST /internal/v1/compute-tasks/:id/resume
//   CancelComputeTask   POST /internal/v1/compute-tasks/:id/cancel
//   SetComputeTaskPriority POST /internal/v1/compute-tasks/:id/priority
//
// Plus VerifyDockCallback: a module's callback endpoint authenticates dock's
// signed completion POST (same HMAC scheme as inbound, keyed by the plugin key).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c *Client) lifecycle(id, action string, body any) error {
	if id == "" {
		return errInvalid("compute-task id required")
	}
	resp, err := c.Do(http.MethodPost, "/internal/v1/compute-tasks/"+id+"/"+action, body)
	if err != nil {
		return err
	}
	return readJSON(resp, nil)
}

// PauseComputeTask: queued → paused. ResumeComputeTask: paused → queued.
// CancelComputeTask: any non-terminal → cancelled.
func (c *Client) PauseComputeTask(id string) error  { return c.lifecycle(id, "pause", nil) }
func (c *Client) ResumeComputeTask(id string) error { return c.lifecycle(id, "resume", nil) }
func (c *Client) CancelComputeTask(id string) error { return c.lifecycle(id, "cancel", nil) }

// SetComputeTaskPriority changes claim order for a not-yet-running task.
func (c *Client) SetComputeTaskPriority(id string, priority int) error {
	return c.lifecycle(id, "priority", map[string]int{"priority": priority})
}

// TaskCallbackPayload is the body dock POSTs to a module's callback_path when a
// task finishes (P3). artifacts carry signed download URLs.
type TaskCallbackPayload struct {
	TaskID       string                `json:"task_id"`
	RequesterRef string                `json:"requester_ref,omitempty"`
	Skill        string                `json:"skill"`
	Status       string                `json:"status"` // done | failed | cancelled
	Result       json.RawMessage       `json:"result,omitempty"`
	Error        string                `json:"error,omitempty"`
	Artifacts    []ComputeTaskArtifact `json:"artifacts"`
}

// VerifyDockCallback authenticates a completion callback from dock. `key` is the
// plugin's HMAC key (DeriveHMACKey(plaintext) — the same value dock signs with),
// `path` is the request path (no host), `tsStr`/`sigHex` come from the
// X-Polar-Plugin-Timestamp / X-Polar-Plugin-Sig headers, and `body` is the raw
// request body. Returns true iff the signature matches and the timestamp is
// within ±300s. Mirrors dock's computePluginSig.
func VerifyDockCallback(key []byte, method, path, tsStr, sigHex string, body []byte) bool {
	if len(key) == 0 || tsStr == "" || sigHex == "" {
		return false
	}
	if ts, err := strconv.ParseInt(tsStr, 10, 64); err != nil {
		return false
	} else if d := time.Now().Unix() - ts; d > 300 || d < -300 {
		return false
	}
	bodySum := sha256.Sum256(body)
	canonical := strings.ToUpper(method) + "\n" + path + "\n" + tsStr + "\n" + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}
