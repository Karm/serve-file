package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
)

func PanicOnWrongSettings(t *testing.T, props [][]string, expectedMessage string, skipPanic ...bool) {
	for _, prop := range props {
		os.Setenv(prop[0], prop[1])
	}
	defer func() {
		for _, prop := range props {
			os.Setenv(prop[0], "")
		}
	}()
	function := func() { LoadSettings() }
	if skipPanic != nil && skipPanic[0] {
		fakeLogPrintf := func(format string, v ...interface{}) {
			assert.Equal(t, expectedMessage, fmt.Sprintf(format, v))
			os.Stdout.WriteString(fmt.Sprintf(format, v))
		}
		patchPrintf := monkey.Patch(log.Printf, fakeLogPrintf)
		defer patchPrintf.Unpatch()
	} else {
		fakeLogFatal := func(msg ...interface{}) {
			assert.Equal(t, expectedMessage, msg[0])
			panic("log.Fatal called")
		}
		patchFatal := monkey.Patch(log.Fatal, fakeLogFatal)
		defer patchFatal.Unpatch()
		assert.PanicsWithValue(t, "log.Fatal called", function, "log.Fatal was not called")
	}
}

func TestCertConfig(t *testing.T) {
	port := []string{"SRV_BIND_PORT", "3000"}
	/*
		CRL
	*/
	props := [][]string{
		port,
		[]string{"SRV_CRL_PEM_BASE64", "-g a rb a g e"},
	}
	PanicOnWrongSettings(t, props, MSG00022)
	props = [][]string{
		port,
		[]string{"SRV_CRL_PEM_BASE64", "Z2FyYmFnZQo="},
	}
	PanicOnWrongSettings(t, props, MSG00025)
	props = [][]string{
		port,
		[]string{"SRV_CRL_PEM_FILE", "/does/not/exist"},
	}
	PanicOnWrongSettings(t, props, MSG00023)
	/*
		CA cert
	*/
	props = [][]string{
		port,
		[]string{"SRV_gaaaarbageCA_CERT_PEM_BASE64", "-g a rb a g e"},
	}
	PanicOnWrongSettings(t, props, MSG00003)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", "-g a rb a g e"},
	}
	PanicOnWrongSettings(t, props, MSG00001)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", "Z2FyYmFnZQo="},
	}
	PanicOnWrongSettings(t, props, MSG00012)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_FILE", "/does/not/exist"},
	}
	PanicOnWrongSettings(t, props, MSG00002)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_FILE", "certs/ca/certs/ca.cert.pem"},
	}
	PanicOnWrongSettings(t, props, MSG00007)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_FILE", "certs/crl/certs/intermediate.crl.pem"},
	}
	PanicOnWrongSettings(t, props, MSG00004)
	/*
		Server key pair
	*/
	caCertBase64 := getBase64("certs/ca/certs/ca.cert.pem")
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", "-g a rb a g e"},
	}
	PanicOnWrongSettings(t, props, MSG00005)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", "Z2FyYmFnZQo="},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", "Z2FyYmFnZQo="},
	}
	PanicOnWrongSettings(t, props, MSG00011)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_BASE64", "Z2FyYmFnZQo="},
		[]string{"SRV_SERVER_KEY_PEM_BASE64", "-g a rb a g e"},
	}
	PanicOnWrongSettings(t, props, MSG00008)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_FILE", "/does/not/exist"},
	}
	PanicOnWrongSettings(t, props, MSG00006)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_CERT_PEM_FILE", "certs/ca/certs/ca.cert.pem"},
		[]string{"SRV_SERVER_KEY_PEM_FILE", "/does/not/exist"},
	}
	PanicOnWrongSettings(t, props, MSG00009)
	props = [][]string{
		port,
		[]string{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		[]string{"SRV_SERVER_KEY_PEM_FILE", "certs/ca/certs/ca.cert.pem"},
		[]string{"SRV_SERVER_CERT_PEM_FILE", "certs/ca/certs/ca.cert.pem"},
	}
	PanicOnWrongSettings(t, props, MSG00011)
	/*
		Port and host and other values for web server config
	*/
	expmsg00001 := "envconfig.Process: assigning SRV_BIND_PORT to BIND_PORT: converting 'qwewqeqwewqe' to type uint16. details: strconv.ParseUint: parsing \"qwewqeqwewqe\": invalid syntax"
	props = [][]string{
		[]string{"SRV_BIND_PORT", "qwewqeqwewqe"},
	}
	PanicOnWrongSettings(t, props, expmsg00001)
	expmsg00002 := "envconfig.Process: assigning SRV_BIND_PORT to BIND_PORT: converting '9283749999999999999993' to type uint16. details: strconv.ParseUint: parsing \"9283749999999999999993\": value out of range"
	props = [][]string{
		[]string{"SRV_BIND_PORT", "9283749999999999999993"},
	}
	PanicOnWrongSettings(t, props, expmsg00002)
	props = [][]string{
		[]string{"SRV_BIND_PORT", "443"},
	}
	PanicOnWrongSettings(t, props, "No SRV_BIND_HOST set, defaulting to localhost", true)
	props = [][]string{
		port,
		[]string{"SRV_BIND_HOST", strings.Repeat("256", 86)},
	}
	PanicOnWrongSettings(t, props, "258 long SRV_BIND_HOST is too long. Could the property be mixed up with a BASE64 cert one?")
}
