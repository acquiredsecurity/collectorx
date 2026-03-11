// Package server implements the web UI HTTP server for forensic-collect.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bradleyroughan/forensic-collect/internal/target"
	"github.com/bradleyroughan/forensic-collect/internal/web"
)

// Server is the forensic-collect web UI HTTP server.
type Server struct {
	Port       int
	TargetsDir string
	Store      *target.TargetStore
	Processors *ProcessorRegistry

	jobs   map[string]*Job
	jobsMu sync.RWMutex
}

// Job tracks a running collection or processing job.
type Job struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Status    string     `json:"status"`
	Error     string     `json:"error,omitempty"`
	StartTime time.Time  `json:"startTime"`
	EndTime   *time.Time `json:"endTime,omitempty"`
	events    chan SSEEvent
	ctx       context.Context
	cancel    context.CancelFunc
}

// SSEEvent is a server-sent event.
type SSEEvent struct {
	Event string `json:"event"`
	Data  any    `json:"data"`
}

// New creates a new web UI server.
func New(port int, targetsDir, asToolsDir string, store *target.TargetStore) *Server {
	return &Server{
		Port:       port,
		TargetsDir: targetsDir,
		Store:      store,
		Processors: NewProcessorRegistry(asToolsDir),
		jobs:       make(map[string]*Job),
	}
}

// Start begins serving the web UI.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Serve embedded static files (index.html)
	mux.Handle("/", http.FileServer(http.FS(web.StaticFiles())))

	// API routes
	mux.HandleFunc("GET /api/targets", s.handleGetTargets)
	mux.HandleFunc("GET /api/processors", s.handleGetProcessors)
	mux.HandleFunc("POST /api/collect", s.handleStartCollect)
	mux.HandleFunc("POST /api/process", s.handleStartProcess)
	mux.HandleFunc("GET /api/jobs/{jobID}/progress", s.handleJobProgress)

	addr := fmt.Sprintf(":%d", s.Port)
	log.Printf("forensic-collect web UI available at http://localhost:%d", s.Port)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) createJob(jobType string) *Job {
	id := fmt.Sprintf("%s_%d", jobType, time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())

	job := &Job{
		ID:        id,
		Type:      jobType,
		Status:    "running",
		StartTime: time.Now(),
		events:    make(chan SSEEvent, 512),
		ctx:       ctx,
		cancel:    cancel,
	}

	s.jobsMu.Lock()
	s.jobs[id] = job
	s.jobsMu.Unlock()

	return job
}

func (s *Server) getJob(id string) *Job {
	s.jobsMu.RLock()
	defer s.jobsMu.RUnlock()
	return s.jobs[id]
}

func (j *Job) sendEvent(event string, data any) {
	select {
	case j.events <- SSEEvent{Event: event, Data: data}:
	default:
		// channel full, drop oldest by reading one then writing
		select {
		case <-j.events:
		default:
		}
		j.events <- SSEEvent{Event: event, Data: data}
	}
}

func (j *Job) complete(summary any) {
	now := time.Now()
	j.Status = "complete"
	j.EndTime = &now
	j.sendEvent("complete", summary)
	close(j.events)
}

func (j *Job) fail(err error) {
	now := time.Now()
	j.Status = "error"
	j.Error = err.Error()
	j.EndTime = &now
	j.sendEvent("error", map[string]string{"error": err.Error()})
	close(j.events)
}

// handleJobProgress streams SSE events for any job type.
func (s *Server) handleJobProgress(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")
	job := s.getJob(jobID)
	if job == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-job.events:
			if !ok {
				return // channel closed, job done
			}
			data, _ := json.Marshal(evt.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, string(data))
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
