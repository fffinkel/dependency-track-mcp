// Command dependency-track-mcp is a read-only Model Context Protocol server
// for OWASP Dependency-Track.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fffinkel/dependency-track-mcp/internal/dtrack"
	"github.com/fffinkel/dependency-track-mcp/internal/tools"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = ""

const usage = `dependency-track-mcp: read-only MCP server for OWASP Dependency-Track

Usage:
  dependency-track-mcp [-http ADDR]

By default the server speaks MCP over stdio. With -http it serves MCP over
streamable HTTP at /mcp, and a health check at /healthz.

Environment:
  DTRACK_URL                  Dependency-Track API server URL. Required.
  DTRACK_API_KEY              API key used for requests that bring no
                              credential of their own. Required over stdio,
                              optional over HTTP.
  DTRACK_MCP_HTTP_ADDR        Same as -http.
  DTRACK_MCP_TIMEOUT          Timeout per request to Dependency-Track.
                              Default 30s.
  DTRACK_MCP_MAX_CONCURRENCY  Requests to Dependency-Track in flight at once.
                              Default 4.

Flags:
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dependency-track-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("dependency-track-mcp", flag.ContinueOnError)
	flags.Usage = func() {
		_, _ = fmt.Fprint(flags.Output(), usage)
		flags.PrintDefaults()
	}
	httpAddr := flags.String("http", os.Getenv("DTRACK_MCP_HTTP_ADDR"), "serve MCP over HTTP on this address, for example 127.0.0.1:8080")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println(buildVersion())
		return nil
	}

	// Logs go to stderr: over stdio, stdout carries the protocol.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	timeout, err := envDuration("DTRACK_MCP_TIMEOUT", 30*time.Second)
	if err != nil {
		return err
	}
	concurrency, err := envInt("DTRACK_MCP_MAX_CONCURRENCY", 4)
	if err != nil {
		return err
	}
	if os.Getenv("DTRACK_URL") == "" {
		return errors.New("DTRACK_URL is not set (the URL of your Dependency-Track API server)")
	}
	client, err := dtrack.New(dtrack.Options{
		BaseURL:        os.Getenv("DTRACK_URL"),
		Timeout:        timeout,
		MaxConcurrency: concurrency,
		UserAgent:      "dependency-track-mcp/" + buildVersion(),
	})
	if err != nil {
		return err
	}

	def := dtrack.Credential{APIKey: os.Getenv("DTRACK_API_KEY")}
	server := mcp.NewServer(&mcp.Implementation{
		Name:       "dependency-track-mcp",
		Title:      "Dependency-Track",
		Version:    buildVersion(),
		WebsiteURL: "https://github.com/fffinkel/dependency-track-mcp",
	}, &mcp.ServerOptions{
		Instructions: "Read-only access to an OWASP Dependency-Track portfolio. " +
			"Start with find_projects to turn an application name into a project UUID. " +
			"To ask where a vulnerability is present, use list_affected_projects instead of reading projects one by one.",
	})
	tools.Register(server, tools.Config{Client: client, Default: def})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr == "" {
		if def.IsZero() {
			return errors.New("DTRACK_API_KEY is not set (required over stdio)")
		}
		err := server.Run(ctx, &mcp.StdioTransport{})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return serveHTTP(ctx, logger, server, *httpAddr, !def.IsZero())
}

func serveHTTP(ctx context.Context, logger *slog.Logger, server *mcp.Server, addr string, sharedKey bool) error {
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		// Stateless: no session to keep, so any replica can serve any
		// request and each request carries its own credential.
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("serving MCP over HTTP", "addr", addr, "path", "/mcp", "shared_api_key", sharedKey, "version", buildVersion())
	if sharedKey {
		logger.Warn("DTRACK_API_KEY is set: requests without their own credential use it, so every caller that can reach this server sees what that key sees")
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q is not a positive duration such as 30s", name, raw)
	}
	return d, nil
}

func envInt(name string, def int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s=%q is not a positive integer", name, raw)
	}
	return n, nil
}
