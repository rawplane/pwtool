// Package logutil provides the shared colourised logger used by metsuke
// for human-readable pipeline output. It mirrors the bash version's
// log / log_ok / log_warn / log_err / log_burp / log_ext helpers.
package logutil

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level is the severity of a log line.
type Level int

const (
	LevelInfo Level = iota
	LevelOK
	LevelWarn
	LevelErr
	LevelBurp
	LevelExt
	LevelSection
)

// Logger writes formatted, colourised log lines. Safe for concurrent use.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	jsonMode bool
}

// New returns a Logger writing to w.
func New(w io.Writer, jsonMode bool) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{w: w, jsonMode: jsonMode}
}

func (l *Logger) log(level Level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.jsonMode {
		l.writeJSON(level, msg)
		return
	}
	l.writeColoured(level, msg)
}

func (l *Logger) writeJSON(level Level, msg string) {
	obj := map[string]string{
		"ts":    time.Now().Format(time.RFC3339),
		"level": levelString(level),
		"msg":   msg,
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	l.w.Write(append(data, '\n'))
}

func (l *Logger) writeColoured(level Level, msg string) {
	ts := time.Now().Format("15:04:05")
	switch level {
	case LevelOK:
		fmt.Fprintf(l.w, "\033[0;32m[%s] [OK]\033[0m %s\n", ts, msg)
	case LevelWarn:
		fmt.Fprintf(l.w, "\033[1;33m[%s] [WARN]\033[0m %s\n", ts, msg)
	case LevelErr:
		fmt.Fprintf(l.w, "\033[0;31m[%s] [ERROR]\033[0m %s\n", ts, msg)
	case LevelBurp:
		fmt.Fprintf(l.w, "\033[0;35m[%s] [BURP]\033[0m %s\n", ts, msg)
	case LevelExt:
		fmt.Fprintf(l.w, "\033[0;35m[%s] [EXT]\033[0m %s\n", ts, msg)
	case LevelSection:
		fmt.Fprintf(l.w, "\n\033[1m\033[0;34m══════════ %s ══════════\033[0m\n", msg)
	default:
		fmt.Fprintf(l.w, "\033[0;36m[%s]\033[0m %s\n", ts, msg)
	}
}

func levelString(level Level) string {
	switch level {
	case LevelOK:
		return "ok"
	case LevelWarn:
		return "warn"
	case LevelErr:
		return "error"
	case LevelBurp:
		return "burp"
	case LevelExt:
		return "ext"
	case LevelSection:
		return "section"
	default:
		return "info"
	}
}

// Public helper methods mirror the bash version's log helpers.

func (l *Logger) Info(format string, args ...any)  { l.log(LevelInfo, format, args...) }
func (l *Logger) OK(format string, args ...any)    { l.log(LevelOK, format, args...) }
func (l *Logger) Warn(format string, args ...any)   { l.log(LevelWarn, format, args...) }
func (l *Logger) Err(format string, args ...any)    { l.log(LevelErr, format, args...) }
func (l *Logger) Burp(format string, args ...any)   { l.log(LevelBurp, format, args...) }
func (l *Logger) Ext(format string, args ...any)    { l.log(LevelExt, format, args...) }
func (l *Logger) Section(format string, args ...any) { l.log(LevelSection, format, args...) }
