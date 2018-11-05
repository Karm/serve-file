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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	caCertFile            = "certs/ca/certs/ca-chain.cert.pem"
	unknownCaCertFile     = "certs/ca/certs/unknown-ca-chain.cert.pem"
	clientCertFile        = "certs/client/certs/client-777.cert.pem"
	unknownClientCertFile = "certs/client/certs/unknown-client.cert.pem"
	caCertBase64          = getBase64(caCertFile)
	serverCertBase64      = getBase64("certs/server/certs/server.cert.pem")
	serverKeyBase64       = getBase64("certs/server/private/server.key.nopass.pem")
	crlBase64             = getBase64("certs/crl/certs/intermediate.crl.pem")
	testMutex             = &sync.Mutex{}
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

func waitUntilZombieLeaves(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ps := exec.Command("ps", "-ef")
		dateOut, _ := ps.CombinedOutput()
		if strings.Contains(string(dateOut), "[openssl] <defunct>") {
			log.Println("[openssl] <defunct> from previous test still present.")
			time.Sleep(1000 * time.Millisecond)
		} else {
			break
		}
	}
}

func startOCSPResponder(timeout time.Duration, ocspURL string, ocspCertName string, caChainCertName string) *exec.Cmd {
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
	}
	ocspCMD := exec.Command("./openssl", cmd...)
	ocspCMD.Start()
	return ocspCMD
}

func interaction(t *testing.T, clientName string, headers []string, expectedHTTPCode string, expectedContent string, props [][]string) {
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
	assert.True(t, strings.Contains(out, expectedHTTPCode), fmt.Sprintf("\"%s\" substring not found in \"%s\".", expectedHTTPCode, out))
}

func TestCorrectClient(t *testing.T) {
	bindPort := "2203"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_API_FILE_DIR", "test-data"},
	}
	interaction(t, "client-666", []string{"-Hx-resolver-id: 666"}, "HTTP/1.1 200",
		"Content-Length: 9000", props)
}

func TestCorrectClientOCSP(t *testing.T) {
	bindPort := "2204"
	ocspPort := "2501"
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
	waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(60*time.Second, ocspPort, "ocsp", "ca-chain")
	defer ocspCMD.Process.Kill()
	defer ocspCMD.Process.Signal(syscall.SIGINT)
	waitForOCSP(30*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	interaction(t, "client-666", []string{"-Hx-resolver-id: 666"}, "HTTP/1.1 200",
		"Content-Length: 9000", props)
}

func TestManyCorrectClients(t *testing.T) {
	bindPort := "2205"
	ocspPort := "2502"
	bindHost := "localhost"
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
	waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(60*time.Second, ocspPort, "ocsp", "ca-chain")
	defer ocspCMD.Process.Kill()
	defer ocspCMD.Process.Signal(syscall.SIGINT)
	waitForOCSP(30*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	for clientNumber := 401; clientNumber < 550; clientNumber++ {
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
	}
}

func TestCorrectClientCached(t *testing.T) {
	bindPort := "2206"
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
	interaction(t, "client-666", headers, "HTTP/1.1 304",
		"136884bffc2743524c8c084c34f1d472", props)
}

func TestCorrectClientNoDataFile(t *testing.T) {
	bindPort := "2207"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	interaction(t, "client-777", []string{"-Hx-resolver-id: 777"}, "HTTP/1.1 466",
		RSP00008, props)
}

func TestCorrectClientNoHashFile(t *testing.T) {
	bindPort := "2208"
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
	interaction(t, "client-400", []string{"-Hx-resolver-id: 400"}, "HTTP/1.1 466",
		RSP00009, props)
}

func TestGarbageCommonName(t *testing.T) {
	bindPort := "2209"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	// Client client-555.cert.pem has CN "5x5x5" instead of "555"
	interaction(t, "client-555", []string{"-Hx-resolver-id: 555"}, "HTTP/1.1 403",
		RSP00006, props)
}

func TestHeaderCertIDDiffers(t *testing.T) {
	bindPort := "2210"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	// Client client-999.cert.pem has CN "9" instead of "999"
	interaction(t, "client-999", []string{"-Hx-resolver-id: 999"}, "HTTP/1.1 403",
		fmt.Sprintf(RSP00007, 9, 999, "x-resolver-id"), props)
}

func TestCorrectClientNoHeader(t *testing.T) {
	bindPort := "2211"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
	}
	interaction(t, "client-777", []string{}, "HTTP/1.1 400", fmt.Sprintf(RSP00005, "x-resolver-id"), props)
}

func TestCRLRevokedClient(t *testing.T) {
	bindPort := "2212"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_CRL_PEM_BASE64", crlBase64},
	}
	interaction(t, "client-888", []string{}, "HTTP/1.1 403", "certificate is revoked in CRL", props)
}

func TestUnknownCertClient(t *testing.T) {
	bindPort := "2213"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
	}
	interaction(t, "unknown-client", []string{}, "alert bad certificate", "", props)
}

func TestOCSPRevokedClient(t *testing.T) {
	bindPort := "2214"
	ocspPort := "2503"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(60*time.Second, ocspPort, "ocsp", "ca-chain")
	defer ocspCMD.Process.Kill()
	defer ocspCMD.Process.Signal(syscall.SIGINT)
	waitForOCSP(30*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	interaction(t, "client-888", []string{}, "HTTP/1.1 403", "certificate is revoked in OCSP", props)
}

func TestWrongOCSP(t *testing.T) {
	bindPort := "2215"
	ocspPort := "2504"
	props := [][]string{
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		[]string{"SRV_BIND_PORT", bindPort},
		[]string{"SRV_BIND_HOST", "localhost"},
		[]string{"SRV_API_URL", "/sinkit/rest/protostream/resolvercache/"},
		[]string{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
	}
	waitUntilZombieLeaves(80 * time.Second)
	ocspCMD := startOCSPResponder(60*time.Second, ocspPort, "unknown-ocsp", "unknown-ca-chain")
	defer ocspCMD.Process.Kill()
	defer ocspCMD.Process.Signal(syscall.SIGINT)
	waitForOCSP(30*time.Second, "http://localhost:"+ocspPort, unknownCaCertFile, unknownClientCertFile)
	interaction(t, "client-888", []string{}, "HTTP/1.1 503", "certificate cannot be validated with OCSP", props)
}
