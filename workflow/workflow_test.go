package workflow

import (
	"testing"
)

func TestIsBound(t *testing.T) {
	s := "bot_x"
	var ti int64 = 5
	cases := []struct {
		name string
		b    TaskBinding
		want bool
	}{
		{"empty", TaskBinding{}, false},
		{"bot only", TaskBinding{BotUserID: &s}, false},
		{"thread only", TaskBinding{ChatThreadID: &ti}, false},
		{"bot+chat", TaskBinding{BotUserID: &s, ChatThreadID: &ti}, true},
		{"all three", TaskBinding{BotUserID: &s, ChatThreadID: &ti, LLMThreadID: &ti}, true},
	}
	for _, c := range cases {
		if got := c.b.IsBound(); got != c.want {
			t.Errorf("%s: IsBound() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestColumns(t *testing.T) {
	if Columns != "bot_user_id, chat_thread_id, llm_thread_id" {
		t.Errorf("Columns drift: %q", Columns)
	}
}

func TestColumnsPrefixed(t *testing.T) {
	if got := ColumnsPrefixed(""); got != Columns {
		t.Errorf("empty prefix: %q != %q", got, Columns)
	}
	want := "t.bot_user_id, t.chat_thread_id, t.llm_thread_id"
	if got := ColumnsPrefixed("t"); got != want {
		t.Errorf("prefix t: got %q, want %q", got, want)
	}
}

func TestInsertArgs(t *testing.T) {
	s := "bot_a"
	var i int64 = 99
	args := InsertArgs(TaskBinding{BotUserID: &s, ChatThreadID: &i})
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
	if args[0] != "bot_a" {
		t.Errorf("args[0] = %v want bot_a", args[0])
	}
	if args[1].(int64) != 99 {
		t.Errorf("args[1] = %v want 99", args[1])
	}
	if args[2] != nil {
		t.Errorf("args[2] = %v want nil", args[2])
	}
}

func TestNullableStringScansNull(t *testing.T) {
	var dst *string = strptr("preexisting")
	scanner := NullableString(&dst)
	if err := scanner.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if dst != nil {
		t.Errorf("dst = %v want nil after SQL NULL", *dst)
	}
}

func TestNullableStringScansValue(t *testing.T) {
	var dst *string
	scanner := NullableString(&dst)
	if err := scanner.Scan("hello"); err != nil {
		t.Fatal(err)
	}
	if dst == nil || *dst != "hello" {
		t.Errorf("dst = %v want \"hello\"", dst)
	}
}

func TestNullableInt64ScansNull(t *testing.T) {
	var dst *int64 = int64ptr(7)
	scanner := NullableInt64(&dst)
	if err := scanner.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if dst != nil {
		t.Errorf("dst = %v want nil after SQL NULL", *dst)
	}
}

func TestNullableInt64ScansValue(t *testing.T) {
	var dst *int64
	scanner := NullableInt64(&dst)
	if err := scanner.Scan(int64(42)); err != nil {
		t.Fatal(err)
	}
	if dst == nil || *dst != 42 {
		t.Errorf("dst = %v want 42", dst)
	}
}

func strptr(s string) *string  { return &s }
func int64ptr(i int64) *int64  { return &i }
