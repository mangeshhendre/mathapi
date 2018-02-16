package tracer

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/peterbourgon/g2s"
	"github.com/quipo/statsd"
)

// Tracer is the struct for the reciever version of this client.
type Tracer struct {
	Client g2s.Statter // The client implementation.
	Sample float32     // The sample rate.
}

// Trace will print the provided string, and return the current time and the provided string.
func Trace(s string) (string, time.Time) {
	log.Println("START:", s)
	return s, time.Now()
}

// Un is meant to be defered and wrapped around trace.
func Un(s string, startTime time.Time) {
	endTime := time.Now()
	log.Println("  END:", s, "ElapsedTime in seconds:", endTime.Sub(startTime)/time.Millisecond)
}

// Statsd sends the stats to statsd instead of stdout.
func Statsd(s string, startTime time.Time) {
	endTime := time.Now()

	client := statsd.NewStatsdClient("graphite:8125", "")
	err := client.CreateSocket()
	if nil != err {
		return
	}
	// Determine our delta.
	delta := int64(endTime.Sub(startTime) / time.Millisecond)
	// Create our message.
	message := strings.TrimSpace(fmt.Sprintf("%s.ElapsedMilliseconds", strings.TrimSpace(s)))
	client.Timing(message, delta)
	client.Close()
}

// New is the method that creates the receiver version.
func New(server, prefix string, sample float32) *Tracer {
	var client g2s.Statter
	var err error
	client, err = g2s.DialWithPrefix("udp", server, prefix)
	if err != nil {
		client = g2s.Noop()
	}
	return &Tracer{
		Client: client,
		Sample: sample,
	}
}

// Statsd sends the stats to statsd instead of stdout.
func (t *Tracer) Statsd(s string, startTime time.Time) {
	// Run in a goroutine so we dont block.
	go t.Client.Timing(t.Sample, s+".ElapsedMilliseconds", time.Since(startTime))
	return
}
