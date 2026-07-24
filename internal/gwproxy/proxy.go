// Package gwproxy implements the raw bidirectional byte copy between a
// client connection and the backend it's authorized to reach.
package gwproxy

import (
	"io"
	"sync"
)

// Pipe copies bytes bidirectionally between a and b until either side
// closes or errors, then closes both and returns. It blocks until both
// directions have finished.
func Pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		a.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		b.Close()
	}()
	wg.Wait()
}
