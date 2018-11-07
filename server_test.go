package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	bindPort              = "2204"
	ocspPort              = "2501"
	bindHost              = "localhost"
	caCertFile            = "certs/ca/certs/ca-chain.cert.pem"
	unknownCaCertFile     = "certs/ca/certs/unknown-ca-chain.cert.pem"
	clientCertFile        = "certs/client/certs/client-777.cert.pem"
	unknownClientCertFile = "certs/client/certs/unknown-client.cert.pem"
)

var (
	caCertBase64     = getBase64(caCertFile)
	serverCertBase64 = getBase64("certs/server/certs/server.cert.pem")
	serverKeyBase64  = getBase64("certs/server/private/server.key.nopass.pem")
	crlBase64        = getBase64("certs/crl/certs/intermediate.crl.pem")
	testMutex        = &sync.Mutex{}
)

func waitForTCP(timeout time.Duration, addrPort string, connShouldFail bool) {
	deadline := time.Now().Add(timeout)
	var con net.Conn
	var err error
	for time.Now().Before(deadline) {
		con, err = net.Dial("tcp", addrPort)
		if connShouldFail {
			if err != nil {
				break
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		} else {
			if err != nil {
				time.Sleep(100 * time.Millisecond)
			} else {
				break
			}
		}
	}
	defer func() {
		if con != nil {
			con.Close()
		}
	}()
}

func waitForOCSP(timeout time.Duration, ocspURL string, caCertFile string, clientCertFile string) {
	caCertBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, caCertBytes := pem.Decode(caCertBytes)
	if block == nil {
		log.Fatal(MSG00012)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clientCertBytes, err := ioutil.ReadFile(clientCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, clientCertBytes = pem.Decode(clientCertBytes)
	if block == nil {
		log.Fatal(MSG00012)
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, ok := certIsRevokedOCSP(clientCert, caCert, ocspURL)
		if ok {
			break
		} else {
			time.Sleep(1000 * time.Millisecond)
		}
	}
}

func stopOCSPResponder(ocspCMD *exec.Cmd) {
	if ocspCMD != nil && ocspCMD.Process != nil {
		ocspCMD.Process.Signal(syscall.SIGINT)
		ocspCMD.Process.Kill()
		time.Sleep(1 * time.Second)
		if ocspCMD.Process != nil {
			ps := exec.Command("kill", "-HUP", fmt.Sprintf("%d", ocspCMD.Process.Pid))
			ps.Wait()
		}
	}
}

func startOCSPResponder(ocspURL string, ocspCertName string, caChainCertName string) *exec.Cmd {
	cmd := []string{
		"ocsp",
		"-port",
		ocspURL,
		"-index",
		"certs/ca/intermediate-index.txt",
		"-CA",
		fmt.Sprintf("certs/ca/certs/%s.cert.pem", caChainCertName),
		"-rkey",
		fmt.Sprintf("certs/ocsp/private/%s.key.nopass.pem", ocspCertName),
		"-rsigner",
		fmt.Sprintf("certs/ocsp/certs/%s.cert.pem", ocspCertName),
		//"-multi",
		//	"1",
		"-nrequest",
		"1000",
		"-timeout",
		"5",
	}
	ocspCMD := exec.Command("./test-data/openssl", cmd...)
	ocspCMD.Start()
	return ocspCMD
}

func interaction(t *testing.T, clientName string, headers []string, expectedHTTPCodes []string, expectedContent string, props [][]string) {
	testMutex.Lock()
	defer testMutex.Unlock()
	var bindHost string
	var bindPort string
	var apiURL string
	for _, prop := range props {
		os.Setenv(prop[0], prop[1])
		if prop[0] == "SRV_BIND_PORT" {
			bindPort = prop[1]
		}
		if prop[0] == "SRV_BIND_HOST" {
			bindHost = prop[1]
		}
		if prop[0] == "SRV_API_URL" {
			apiURL = prop[1]
		}
	}
	defer func() {
		for _, prop := range props {
			os.Setenv(prop[0], "")
		}
	}()
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), true)
	go main()
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), false)
	curl := []string{
		fmt.Sprintf("https://%s:%s%s", bindHost, bindPort, apiURL),
		"--cert",
		fmt.Sprintf("certs/client/certs/%s.cert.pem", clientName),
		"--key",
		fmt.Sprintf("certs/client/private/%s.key.nopass.pem", clientName),
		"--cacert",
		"certs/ca/certs/ca-chain.cert.pem",
		"-i",
		"-v",
	}
	dateCmd := exec.Command("curl", append(curl, headers...)...)
	dateOut, err := dateCmd.CombinedOutput()
	if len(expectedContent) > 0 {
		assert.Equal(t, err, nil)
	}
	out := string(dateOut)
	assert.True(t, strings.Contains(out, expectedContent), fmt.Sprintf("\"%s\" substring not found in \"%s\".", expectedContent, out))
	found := false
	for _, expectedHTTPCode := range expectedHTTPCodes {
		if strings.Contains(out, expectedHTTPCode) {
			found = true
			break
		}
	}
	assert.True(t, found, fmt.Sprintf("None of \"%s\" expected substrings found in \"%s\".", expectedHTTPCodes, out))
}

func TestCorrectClient(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_API_FILE_DIR", "test-data"},
	}
	interaction(t, "client-666", []string{"-Hx-resolver-id: 666"}, []string{"HTTP/1.1 200"},
		"Content-Length: 9000", props)
}

func TestCorrectClientOCSP(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_API_FILE_DIR", "test-data"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	//waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(ocspPort, "ocsp", "ca-chain")
	defer stopOCSPResponder(ocspCMD)
	waitForOCSP(5*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	interaction(t, "client-666", []string{"-Hx-resolver-id: 666"}, []string{"HTTP/1.1 200"},
		"Content-Length: 9000", props)
}

func TestManyCorrectClients(t *testing.T) {
	apiURL := "/sinkit/rest/protostream/resolvercache/"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", bindHost},
		[]string{"SRV_API_URL", apiURL},
		[]string{"SRV_API_FILE_DIR", "test-data"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	for _, prop := range props {
		os.Setenv(prop[0], prop[1])
	}
	defer func() {
		for _, prop := range props {
			os.Setenv(prop[0], "")
		}
	}()
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), true)
	go main()
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), false)
	//waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(ocspPort, "ocsp", "ca-chain")
	defer stopOCSPResponder(ocspCMD)
	waitForOCSP(5*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	var doneRoutines uint32
	for clientNumber := 401; clientNumber < 550; clientNumber++ {
		go func(clientNumber int) {
			curl := []string{
				fmt.Sprintf("https://%s:%s%s", bindHost, bindPort, apiURL),
				"--cert",
				fmt.Sprintf("certs/client/certs/client-%d.cert.pem", clientNumber),
				"--key",
				fmt.Sprintf("certs/client/private/client-%d.key.nopass.pem", clientNumber),
				"--cacert",
				"certs/ca/certs/ca-chain.cert.pem",
				"-i",
				"-v",
			}
			dateCmd := exec.Command("curl", append(curl, []string{fmt.Sprintf("-Hx-resolver-id: %d", clientNumber)}...)...)
			dateOut, err := dateCmd.CombinedOutput()
			assert.Equal(t, err, nil)
			out := string(dateOut)
			expectedContent := fmt.Sprintf("Content-Length: %d", clientNumber)
			assert.True(t, strings.Contains(out, expectedContent), fmt.Sprintf("\"%s\" substring not found in \"%s\".", expectedContent, out))
			assert.True(t, strings.Contains(out, "HTTP/1.1 200"), fmt.Sprintf("\"%s\" substring not found in \"%s\".", "HTTP/1.1 200", out))
			atomic.AddUint32(&doneRoutines, 1)
		}(clientNumber)
	}
	for atomic.LoadUint32(&doneRoutines) < 149 {
		log.Println("Waiting for all clients to complete.")
		time.Sleep(500 * time.Millisecond)
	}
}

func TestCorrectClientCached(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_API_FILE_DIR", "test-data"},
	}
	headers := []string{
		"-Hx-resolver-id: 666",
		"-HIf-None-Match: \"136884bffc2743524c8c084c34f1d472\"",
	}
	interaction(t, "client-666", headers, []string{"HTTP/1.1 304"},
		"136884bffc2743524c8c084c34f1d472", props)
}

func TestCorrectClientNoDataFile(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	interaction(t, "client-777", []string{"-Hx-resolver-id: 777"}, []string{"HTTP/1.1 466"},
		RSP00008, props)
}

func TestCorrectClientNoHashFile(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_API_FILE_DIR", "test-data"},
	}
	// There is no 400_resolver_cache.bin.md5 file to accompany 400_resolver_cache.bin
	interaction(t, "client-400", []string{"-Hx-resolver-id: 400"}, []string{"HTTP/1.1 466"},
		RSP00009, props)
}

func TestGarbageCommonName(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	// Client client-555.cert.pem has CN "5x5x5" instead of "555"
	interaction(t, "client-555", []string{"-Hx-resolver-id: 555"}, []string{"HTTP/1.1 403"},
		RSP00006, props)
}

func TestHeaderCertIDDiffers(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	// Client client-999.cert.pem has CN "9" instead of "999"
	interaction(t, "client-999", []string{"-Hx-resolver-id: 999"}, []string{"HTTP/1.1 403"},
		fmt.Sprintf(RSP00007, 9, 999, "x-resolver-id"), props)
}

func TestCorrectClientNoHeader(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	interaction(t, "client-777", []string{}, []string{"HTTP/1.1 400"}, fmt.Sprintf(RSP00005, "x-resolver-id"), props)
}

func TestCRLRevokedClient(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_CRL_PEM_BASE64", crlBase64},
	}
	interaction(t, "client-888", []string{}, []string{"HTTP/1.1 403"}, "certificate is revoked in CRL", props)
}

func TestUnknownCertClient(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
	}
	interaction(t, "unknown-client", []string{}, []string{"SSL_ERROR_BAD_CERT_ALERT", "alert bad certificate"}, "", props)
}

func TestOCSPRevokedClient(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	//waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(ocspPort, "ocsp", "ca-chain")
	defer stopOCSPResponder(ocspCMD)
	waitForOCSP(5*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	interaction(t, "client-888", []string{}, []string{"HTTP/1.1 403"}, "certificate is revoked in OCSP", props)
}

func TestWrongOCSP(t *testing.T) {
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	//waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(ocspPort, "unknown-ocsp", "unknown-ca-chain")
	defer stopOCSPResponder(ocspCMD)
	waitForOCSP(5*time.Second, "http://localhost:"+ocspPort, unknownCaCertFile, unknownClientCertFile)
	interaction(t, "client-888", []string{}, []string{"HTTP/1.1 503"}, "certificate cannot be validated with OCSP", props)
}
