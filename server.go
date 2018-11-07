package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "1.0.0"

func createServer(settings *Settings) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(settings.API_URL, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if r.TLS == nil {
			log.Printf(RSL00001)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00001)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		idFromCertStr := string(r.TLS.VerifiedChains[0][0].Subject.CommonName)
		var idFromCert int64
		idFromCert, err := strconv.ParseInt(idFromCertStr, 10, 64)
		if err != nil {
			log.Printf(RSL00006)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00006)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if settings.crl != nil && certIsRevokedCRL(r.TLS.VerifiedChains[0][0], settings.crl) {
			log.Printf(RSL00002, idFromCertStr)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00002)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if len(settings.OCSP_URL) > 0 {
			if revoked, ok := certIsRevokedOCSP(r.TLS.VerifiedChains[0][0], settings.caCert, settings.OCSP_URL); !ok {
				log.Printf(RSL00003, idFromCertStr, settings.OCSP_URL)
				w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00003)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			} else if revoked {
				log.Printf(RSL00004, idFromCertStr, settings.OCSP_URL)
				w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00004)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		var idFromHeader int64
		idFromHeader, err = strconv.ParseInt(
			strings.Trim(r.Header.Get(settings.API_ID_REQ_HEADER), " "), 10, 64)
		if err != nil {
			log.Printf(RSL00005, idFromCertStr, settings.API_ID_REQ_HEADER)
			w.Header().Set(settings.API_RSP_ERROR_HEADER,
				fmt.Sprintf(RSP00005, settings.API_ID_REQ_HEADER))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if idFromCert != idFromHeader {
			log.Printf(RSL00007, idFromCert, idFromHeader, settings.API_ID_REQ_HEADER)
			w.Header().Set(settings.API_RSP_ERROR_HEADER,
				fmt.Sprintf(RSP00007, idFromCert, idFromHeader, settings.API_ID_REQ_HEADER))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		pathToDataFile := fmt.Sprintf(
			settings.API_DATA_FILE_TEMPLATE,
			settings.API_FILE_DIR,
			idFromCertStr,
		)
		// We do not read the file in memory, just metadata to check it exists.
		_, err = os.Stat(pathToDataFile)
		if err != nil {
			log.Printf(RSL00008, pathToDataFile, idFromCert)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00008)
			w.WriteHeader(settings.API_RSP_TRY_LATER_HTTP_CODE)
			return
		}
		pathToHashFile := fmt.Sprintf(
			settings.API_HASH_FILE_TEMPLATE,
			settings.API_FILE_DIR,
			idFromCertStr,
		)
		// We do read the hash file at once, just 32 bytes...
		hash, err := ioutil.ReadFile(pathToHashFile)
		if err != nil {
			log.Printf(RSL00009, pathToHashFile, idFromCert, pathToDataFile)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, RSP00009)
			w.WriteHeader(settings.API_RSP_TRY_LATER_HTTP_CODE)
			return
		}
		etag := "\"" + string(hash) + "\"" // Well, we know the size of byte[], do we really need all those extra allocs?
		// https://tools.ietf.org/html/rfc7232#section-2.3
		w.Header().Set("ETag", etag)
		// https://tools.ietf.org/html/rfc7232#section-3.2
		if etag == r.Header.Get("If-None-Match") {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.ServeFile(w, r, pathToDataFile)
		return
	})
	tlsCfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    settings.caCertPool,
		Certificates: []tls.Certificate{settings.serverKeyPair},
	}
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", settings.BIND_HOST, settings.BIND_PORT),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadTimeout:       time.Duration(settings.READ_TIMEOUT_S) * time.Second,
		ReadHeaderTimeout: time.Duration(settings.READ_HEADER_TIMEOUT_S) * time.Second,
		WriteTimeout:      time.Duration(settings.WRITE_TIMEOUT_S) * time.Second,
		IdleTimeout:       time.Duration(settings.IDLE_TIMEOUT_S) * time.Second,
		MaxHeaderBytes:    settings.MAX_HEADER_BYTES,
	}
	return srv
}

func main() {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	settings := LoadSettings()
	srv := createServer(&settings)
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsListener := tls.NewListener(l, srv.TLSConfig)
	go func(s *http.Server) {
		if err := srv.Serve(tlsListener); err != nil {
			log.Println(err)
		}
	}(srv)
	go func(s *http.Server) {
		sig := <-sigs
		log.Println(sig)
		if err := srv.Shutdown(nil); err != nil {
			log.Fatal(err)
		}
		done <- true
	}(srv)
	log.Printf("Running version %s. Ctrl+C to stop.", version)
	<-done
	log.Printf("Stopped.")
}
