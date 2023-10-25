package models

type FailSeverity int

const (
	UNDEFINED FailSeverity = 10
	LOW       FailSeverity = 11
	MODERATE  FailSeverity = 12
	HIGH      FailSeverity = 13
	CRITICAL  FailSeverity = 14
)
