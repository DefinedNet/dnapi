package testutil

import (
	"io"
	"log/slog"
	"os"
)

// NewTestLogger returns a *slog.Logger configured for testing (e.g.
// end-to-end tests, unit tests, etc.). Set the TEST_LOGS environment
// variable to 1/2/3 to raise the verbosity from info to debug/trace.
func NewTestLogger() *slog.Logger {
	level := slog.LevelInfo
	out := io.Discard

	switch os.Getenv("TEST_LOGS") {
	case "":
		// Keep the discard writer and info level default.
	case "1":
		out = os.Stdout
	case "2":
		out = os.Stdout
		level = slog.LevelDebug
	case "3":
		out = os.Stdout
		level = slog.Level(-8) // trace-equivalent; below Debug
	default:
		out = os.Stdout
	}

	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: level,
	}))
}
