package gomap

import (
	"math/rand"
	"strings"
	"unicode"
)

// ToScriptKiddie converts normal output to "script kiddie" format (-oS).
// This is nmap's joke output mode that replaces characters with leet-speak.
func ToScriptKiddie(normal string) string {
	var b strings.Builder
	b.Grow(len(normal))

	for _, r := range normal {
		if unicode.IsUpper(r) {
			b.WriteRune(leetChar(unicode.ToLower(r)))
		} else {
			b.WriteRune(leetChar(r))
		}
	}
	return b.String()
}

func leetChar(r rune) rune {
	switch r {
	case 'a':
		if rand.Intn(2) == 0 {
			return '4'
		}
		return '@'
	case 'e':
		return '3'
	case 'i':
		if rand.Intn(2) == 0 {
			return '1'
		}
		return '!'
	case 'o':
		return '0'
	case 's':
		if rand.Intn(2) == 0 {
			return '5'
		}
		return '$'
	case 't':
		return '7'
	case 'l':
		return '1'
	default:
		// Randomly capitalize
		if rand.Intn(3) == 0 {
			return unicode.ToUpper(r)
		}
		return r
	}
}
