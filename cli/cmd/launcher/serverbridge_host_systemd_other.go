//go:build !linux

package main

func hostServiceReady02811(_ serverBridgeHostRuntime01910)     {}
func hostServiceStopping02811()                                {}
func hostServiceStatus02811(_ string)                          {}
func hostServiceRun02811(_ map[string]string, _ string) func() { return func() {} }
