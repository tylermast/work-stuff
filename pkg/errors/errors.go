package errors

import "log"

func HandleFatalError(e error, s string) {
	if e != nil {
		log.Fatalf("Fatal error: %s\n%s", s, e)
	}
}

func LogError(e error, s string) {
	if e != nil {
		log.Printf("Error: %s\n%s", s, e)
	}
}
