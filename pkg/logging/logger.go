/*
Copyright 2020- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logging

import (
	"fmt"
	"log"
	"runtime"
	"sync"
)

var Logger DefaultLogger
var once sync.Once

// Verbosity is an enumerated type for defining the level of verbosity.
type Verbosity int

const (
	LowVerbosity    Verbosity = iota // LowVerbosity only reports errors
	MediumVerbosity                  // MediumVerbosity reports warnings and errors
	HighVerbosity                    // HighVerbosity reports infos, warnings and errors
)

// DefaultLogger is the package's built-in logger. It uses log.Default() as the underlying logger.
type DefaultLogger struct {
	verbosity Verbosity
	l         *log.Logger
}

// NewDefaultLogger creates an instance of DefaultLogger with the highest verbosity.
func NewDefaultLogger() *DefaultLogger {
	return NewDefaultLoggerWithVerbosity(HighVerbosity)
}

// NewDefaultLoggerWithVerbosity creates an instance of DefaultLogger with a user-defined verbosity.
func NewDefaultLoggerWithVerbosity(verbosity Verbosity) *DefaultLogger {
	return &DefaultLogger{
		verbosity: verbosity,
		l:         log.Default(),
	}
}

// Init initializes a thread-safe singleton logger
// This would be called from a main method when the application starts up
func Init(verbosity Verbosity) {
	// once ensures the singleton is initialized only once
	once.Do(func() {
		Logger = *NewDefaultLoggerWithVerbosity(verbosity)
	})
}

// Debugf writes a debug message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
func Debugf(format string, o ...interface{}) {
	if Logger.verbosity == HighVerbosity {
		pc, _, _, _ := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		Logger.l.Printf("DEBUG	%s	%s", details.Name(), fmt.Sprintf(format, o...))
	}
}

// Infof writes an informative message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
func Infof(format string, o ...interface{}) {
	if Logger.verbosity == HighVerbosity {
		pc, _, _, _ := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		Logger.l.Printf("INFO	%s	%s", details.Name(), fmt.Sprintf(format, o...))
	}
}

// Warnf writes a warning message to the log (unless DefaultLogger verbosity is set to LowVerbosity)
func Warnf(format string, o ...interface{}) {
	if Logger.verbosity >= MediumVerbosity {
		pc, _, _, _ := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		Logger.l.Printf("WARN	%s	%s", details.Name(), fmt.Sprintf(format, o...))
	}
}

// ReturnError writes an error message to the log (only if DefaultLogger verbosity is set to HighVerbosity)
// and returns the error message
func ReturnErrorf(format string, o ...interface{}) error {
	if Logger.verbosity == HighVerbosity {
		pc, _, _, _ := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		Logger.l.Printf("ERROR	%s:	%s", details.Name(), fmt.Sprintf(format, o...))
	}
	return fmt.Errorf(format, o...)
}
