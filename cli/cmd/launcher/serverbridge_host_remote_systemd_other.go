//go:build !linux

package main

import "context"

func remoteServiceReady0498() error             { return nil }
func remoteServiceStopping0498()                {}
func remoteServiceWatchdog0498(context.Context) {}
