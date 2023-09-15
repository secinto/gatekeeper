/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package handlers

import (
	"net/http"
	"net/http/pprof"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	proxycore "github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
)

// EmptyHandler is responsible for doing nothing
func EmptyHandler(_ http.ResponseWriter, _ *http.Request) {}

// HealthHandler is a health check handler for the service
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(constant.VersionHeader, proxycore.GetVersion())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

// DebugHandler is responsible for providing the pprof
//
//nolint:cyclop
func DebugHandler(writer http.ResponseWriter, req *http.Request) {
	const symbolProfile = "symbol"

	name := chi.URLParam(req, "name")

	switch req.Method {
	case http.MethodGet:
		switch name {
		case "heap":
			fallthrough
		case "goroutine":
			fallthrough
		case "block":
			fallthrough
		case "threadcreate":
			pprof.Handler(name).ServeHTTP(writer, req)
		case "cmdline":
			pprof.Cmdline(writer, req)
		case "profile":
			pprof.Profile(writer, req)
		case "trace":
			pprof.Trace(writer, req)
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPost:
		switch name {
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

func MethodNotAllowHandlder(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write(nil)
}
