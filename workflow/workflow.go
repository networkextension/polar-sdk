// Package workflow encodes the "task → bot → chat_thread → llm_thread"
// binding pattern shared across plugins. polar-projects pioneered it
// on project_tasks; polar-buildings reuses it on work_orders +
// inspections; polar-lawyer's cases will land on it too.
//
// Why a shared package: each plugin owns its own domain tables, but
// the three binding columns (bot_user_id TEXT NULL, chat_thread_id
// BIGINT NULL, llm_thread_id BIGINT NULL) show up identically
// everywhere. Co-locating the Go type + DB column strings + scanner
// shims here means future contract changes (e.g. dock starts requiring
// workspace_id on chat-thread create) flow through one file.
//
// What this package owns today:
//   - TaskBinding — Go type for the three columns + IsBound()
//   - Columns / ColumnsPrefixed — SELECT/INSERT column-list constants
//   - NullableString / NullableInt64 — sql.Scanner shims that write
//     into *T (so the binding fields can stay *string / *int64 rather
//     than dragging sql.NullString through plugin call sites)
//   - InsertArgs — []any builder matching the Columns order, for
//     positional INSERTs
//
// What it deliberately does NOT own (yet):
//   - Domain table DDL — each plugin defines its own columns next to
//     the binding; only the binding spelling is shared.
//   - dock RPC wrappers (EnsureChatThread / CloseChatThread / …) —
//     wait for dock to expose those internal endpoints. Once it does,
//     this package will grow method receivers on *sdk.Client.
//   - Revision / retrospect / dispatch tables — they're also patterns
//     in polar-projects but they're table-shaped, not column-shaped.
//     Cross-plugin sharing will happen as documentation + sql snippet
//     copies until a second consumer actually wants them; resist the
//     urge to abstract from a sample size of one.
package workflow

import (
	"database/sql"
)

// TaskBinding is the (bot_user_id, chat_thread_id, llm_thread_id)
// triple every plugin's task-shaped table carries.
//
// All three fields are nullable because:
//   - A task may be authored by a human and never assigned a bot.
//   - A bot may be assigned before a chat_thread is allocated (e.g.
//     dock is reachable from the request path but the chat-thread
//     create is queued).
//   - llm_thread_id lags chat_thread_id — the bot is bound to the
//     thread before the LLM session is established.
type TaskBinding struct {
	BotUserID    *string `json:"bot_user_id,omitempty"`
	ChatThreadID *int64  `json:"chat_thread_id,omitempty"`
	LLMThreadID  *int64  `json:"llm_thread_id,omitempty"`
}

// IsBound reports whether the task has at least the bot + chat-thread
// pair. LLM thread is intentionally not required — see TaskBinding doc.
func (b TaskBinding) IsBound() bool {
	return b.BotUserID != nil && b.ChatThreadID != nil
}

// Columns is the column list for SELECT statements scanning a binding,
// in canonical order. Pair with NullableString / NullableInt64 (or
// InsertArgs for inserts) to keep call sites in lockstep.
const Columns = "bot_user_id, chat_thread_id, llm_thread_id"

// ColumnsPrefixed returns the same three columns qualified with the
// given table alias. Pass "" for unprefixed (equivalent to Columns).
func ColumnsPrefixed(prefix string) string {
	if prefix == "" {
		return Columns
	}
	return prefix + ".bot_user_id, " + prefix + ".chat_thread_id, " + prefix + ".llm_thread_id"
}

// NullableString returns a sql.Scanner that, on a successful Scan,
// writes the value into *dst (nil for SQL NULL). Lets plugin scan
// code keep the binding fields as *string rather than carrying
// sql.NullString through every call site.
//
//	var b workflow.TaskBinding
//	row.Scan(&id, &title, &status,
//	    workflow.NullableString(&b.BotUserID),
//	    workflow.NullableInt64(&b.ChatThreadID),
//	    workflow.NullableInt64(&b.LLMThreadID),
//	)
func NullableString(dst **string) sql.Scanner {
	return &nullableString{dst: dst}
}

type nullableString struct{ dst **string }

func (n *nullableString) Scan(src any) error {
	var v sql.NullString
	if err := v.Scan(src); err != nil {
		return err
	}
	if v.Valid {
		s := v.String
		*n.dst = &s
	} else {
		*n.dst = nil
	}
	return nil
}

// NullableInt64 is the int64 counterpart of NullableString.
func NullableInt64(dst **int64) sql.Scanner {
	return &nullableInt64{dst: dst}
}

type nullableInt64 struct{ dst **int64 }

func (n *nullableInt64) Scan(src any) error {
	var v sql.NullInt64
	if err := v.Scan(src); err != nil {
		return err
	}
	if v.Valid {
		i := v.Int64
		*n.dst = &i
	} else {
		*n.dst = nil
	}
	return nil
}

// InsertArgs returns the three values in canonical Columns order,
// nil-safe for the SQL driver:
//
//	INSERT INTO work_orders (id, title, bot_user_id, chat_thread_id, llm_thread_id)
//	VALUES ($1, $2, $3, $4, $5)
//
//	args := append([]any{id, title}, workflow.InsertArgs(binding)...)
//	db.Exec(query, args...)
func InsertArgs(b TaskBinding) []any {
	return []any{stringArg(b.BotUserID), int64Arg(b.ChatThreadID), int64Arg(b.LLMThreadID)}
}

func stringArg(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func int64Arg(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
