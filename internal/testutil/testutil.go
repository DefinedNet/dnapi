package testutil

import (
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

// NewTestLogger returns a *logrus.Logger struct configured for testing (e.g. end-to-end tests, unit tests, etc.)
func NewTestLogger() *logrus.Logger {
	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp: true,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyMsg: "message",
		},
	})

	v := os.Getenv("TEST_LOGS")
	if v == "" {
		l.SetOutput(ioutil.Discard)
		return l
	}

	switch v {
	case "1":
		// This is the default level but we are being explicit
		l.SetLevel(logrus.InfoLevel)
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	}

	return l
}
