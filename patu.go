package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const applicationName = "patu"
const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789"
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
var src = rand.NewSource(time.Now().UnixNano())
var hostname = GetHostname()
var egressIP = GetEgressIP()

var BuildBranch string
var BuildVersion string
var BuildTime string
var BuildRevision string

var flagListen string
var flagVersion bool
var flagVerbose bool
var flagPIDFile string

var (
	metricsConnectionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: applicationName + "_connections_total",
		Help: "The total number of connections",
	})
	metricsUriTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: applicationName + "_uri_total",
		Help: "The total number of rquest per uri",
	}, []string{"uri"})
)

func main() {
	log.Printf("%s version %s (Rev: %s Branch: %s) built on %s", applicationName, BuildVersion, BuildRevision, BuildBranch, BuildTime)
	parseFlags()

	httpServerStart()
}

func httpServerStart() {
	var buildInfoMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: applicationName + "_build_info", Help: "Shows the build info/version",
		ConstLabels: prometheus.Labels{"branch": BuildBranch, "revision": BuildRevision, "version": BuildVersion, "buildTime": BuildTime, "goversion": runtime.Version()}})
	prometheus.MustRegister(buildInfoMetric)
	buildInfoMetric.Set(1)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", indexServer)
	http.HandleFunc("/rand", randServer2) // 2 is much faster
	http.HandleFunc("/rand1", randServer1)
	http.HandleFunc("/rand2", randServer2)
	http.HandleFunc("/echo", echoServer)
	http.HandleFunc("/space", spaceServer1)
	http.HandleFunc("/space1", spaceServer1)
	http.HandleFunc("/hash", hashServer)
	http.HandleFunc("/ip", ipServer)
	http.HandleFunc("/melt", meltServer)
	http.HandleFunc("/test-long", testLongServer)

	if err := http.ListenAndServe(flagListen, nil); err != nil {
		log.Fatalf("FATAL: Failed to start http engine - %v", err)
	}
	log.Printf("%s started from %s (%s) on %s\n", applicationName, hostname, egressIP, flagListen)
}

func parseFlags() {
	flag.StringVar(&flagListen, "listen", "0.0.0.0:80", "listen <host>:<port>")
	flag.StringVar(&flagPIDFile, "pidfile", "", "pidfile")
	flag.BoolVar(&flagVerbose, "verbose", false, "verbose flag")
	flag.BoolVar(&flagVersion, "version", false, "get version")
	flag.Parse()
	if flagVersion { // Only print version (We always print version), then exit.
		os.Exit(0)
	}
	if len(flagPIDFile) > 0 {
		log.Printf("Will save process ID %d to pidfile %s", os.Getpid(), flagPIDFile)
		deferCleanup() // This installs a handler to remove PID file when we quit
		savePIDFile(flagPIDFile)
	}
}

func deferCleanup() { // Installs a handler to perform clean up
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE)
	go func() {
		<-c
		cleanup()
		os.Exit(1)
	}()

}

func cleanup() {
	if len(flagPIDFile) > 0 {
		os.Remove(flagPIDFile)
	}
	log.Printf("%s perform clean up on process end", applicationName)

}

func savePIDFile(pidFile string) {
	file, err := os.Create(pidFile)
	if err != nil {
		log.Fatalf("Unable to create pid file : %v", err)
	}
	defer file.Close()

	pid := os.Getpid()
	if _, err = file.WriteString(strconv.Itoa(pid)); err != nil {
		log.Fatalf("Unable to create pid file : %v", err)
	}
	if flagVerbose {
		log.Printf("Wrote PID %0d to %s", pid, flagPIDFile)
	}

	file.Sync() // flush to disk

}

func timeStampIso() string {
	current_time := time.Now()
	return current_time.Format(time.RFC3339)
}

func indexServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": "/"}).Inc() // We use / as its default handler
	fmt.Fprintf(w, "Hello %s from %s (%s)!\n", ReadUserIP(r), hostname, egressIP)
}

func testLongServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	fmt.Fprintf(w, "[%s] Starting a long request\n", timeStampIso())
	log.Printf("Conection from %s", r.RemoteAddr)
	time.Sleep(5 * time.Second)
	fmt.Fprintf(w, "[%s] Continue a long request\n", timeStampIso())
	time.Sleep(5 * time.Second)
	fmt.Fprintf(w, "[%s] Continue a long request\n", timeStampIso())
	log.Printf("Conection closing %s", r.RemoteAddr)
}

func ipServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	fmt.Fprintf(w, "%s", ReadUserIP(r))
}

func randServer2(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var size = 1024 // Default of 1024 chars
	keys, ok := r.URL.Query()["size"]

	if ok && len(keys[0]) > 0 {
		readsize, err := strconv.ParseInt(keys[0], 10, 32)
		if err != nil {
			readsize = 1024
		} else if readsize <= 0 {
			readsize = 1024
		}
		size = int(readsize)
	}
	fmt.Fprintf(w, "%s\n", RandStringBytesMaskImprSrcUnsafe(size))
}

func randServer1(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var size = 1024 // Default of 1024 chars
	keys, ok := r.URL.Query()["size"]

	if ok && len(keys[0]) > 0 {
		readsize, err := strconv.ParseInt(keys[0], 10, 32)
		if err != nil {
			readsize = 1024
		} else if readsize <= 0 {
			readsize = 1024
		}
		size = int(readsize)
	}
	fmt.Fprintf(w, "%s\n", RandString(size))
}

func hashServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var input = ""
	var hash = "md5"
	keys1, ok1 := r.URL.Query()["string"]
	keys2, ok2 := r.URL.Query()["hash"]

	if ok1 && len(keys1[0]) > 0 {
		input = keys1[0]
	}
	if ok2 && len(keys2[0]) > 0 {
		hash = keys2[0]
	}
	if hash == "sha256" {
		fmt.Fprintf(w, "%s\n", GetSha256Hash(input))
	} else {
		fmt.Fprintf(w, "%s\n", GetMD5Hash(input))
	}
}

func meltServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var size = 1024 // Default of 1024 chars
	keys, ok := r.URL.Query()["size"]

	if ok && len(keys[0]) > 0 {
		readsize, err := strconv.ParseInt(keys[0], 10, 32)
		if err != nil {
			readsize = 1024
		} else if readsize <= 0 {
			readsize = 1024
		}
		size = int(readsize)
	}
	for i := 0; i < size; i++ {
		fmt.Fprintf(w, "%s\n", GetSha256Hash(RandString(65536)))
	}
}

func echoServer(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var input = " "
	keys, ok := r.URL.Query()["string"]

	if ok && len(keys[0]) > 0 {
		input = keys[0]
	}
	fmt.Fprintf(w, "%s\n", input)
}

func spaceServer1(w http.ResponseWriter, r *http.Request) {
	metricsConnectionTotal.Inc()
	metricsUriTotal.With(prometheus.Labels{"uri": r.URL.Path}).Inc()
	var size = 1024 // Default of 1024 chars
	keys, ok := r.URL.Query()["size"]

	if ok && len(keys[0]) > 0 {
		readsize, err := strconv.ParseInt(keys[0], 10, 32)
		if err != nil {
			readsize = 1024
		} else if readsize <= 0 {
			readsize = 1024
		}
		size = int(readsize)
	}

	fmt.Fprintf(w, fmt.Sprintf("%%%0ds", size), "")
}

func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	if strings.ContainsRune(IPAddress, ':') {
		IPAddress, _, _ = net.SplitHostPort(IPAddress)
	}
	return IPAddress
}

func RandStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandString(length int) string {
	return RandStringWithCharset(length, charset)
}

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
	// https://github.com/TheLinker/gorrent/blob/master/libgorrent/RandStringBytesMaskImprSrcUnsafe.go
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func GetEgressIP() string {
	conn, error := net.Dial("udp", "1.1.1.1:80")
	if error != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	iPAddress := conn.LocalAddr().(*net.UDPAddr).String()
	if strings.ContainsRune(iPAddress, ':') {
		iPAddress, _, _ = net.SplitHostPort(iPAddress)
	}
	return iPAddress
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func GetHostname() string {
	name, err := os.Hostname()
	if err == nil {
		return name
	} else {
		return "localhost"
	}
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetSha256Hash(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
