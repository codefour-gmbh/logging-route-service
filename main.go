package main

import (
    "bytes"
    "crypto/tls"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "strconv"
    "time"
    "strings"
    "regexp"
)

const (
    DEFAULT_PORT              = "8080"
    FORWARDED_FOR_HEADER      = "X-Forwarded-For"
    CF_FORWARDED_URL_HEADER   = "X-Cf-Forwarded-Url"
    CF_PROXY_SIGNATURE_HEADER = "X-Cf-Proxy-Signature"
)

func main() {
    var (
        access_list     []string
        port              string
        skipSslValidation bool
        err               error
    )
    
    log.SetOutput(os.Stdout)
    
    env_limit := os.Getenv("ACCESS_LIST")
    if len(env_limit) != 0 {
        isIP := regexp.MustCompile(`^[0-9.]+$`).MatchString
        
        log.Printf("Limiting ip access to: [%d]\n", env_limit)
        access_list = strings.Split(env_limit, " ")
        for _, v := range access_list {
            if (!isIP(v) || strings.Count(v, ".") != 3) {
                log.Printf("Resolving ip for: [%d]\n", v)
                addr, err := net.LookupHost(v)
                log.Printf("Error ? ", err)
                for k, a := range addr {
                    log.Printf("IP " + string(k) + ": " + string(a))
                    access_list = append(access_list, a)
                }
            }
        }
    }
    if port = os.Getenv("PORT"); len(port) == 0 {
        port = DEFAULT_PORT
    }
    if skipSslValidation, err = strconv.ParseBool(os.Getenv("SKIP_SSL_VALIDATION")); err != nil {
        skipSslValidation = true
    }

    roundTripper := NewLoggingRoundTripper(access_list, skipSslValidation)
    proxy := NewProxy(roundTripper, skipSslValidation)

    log.Fatal(http.ListenAndServe(":"+port, proxy))
}

func NewProxy(transport http.RoundTripper, skipSslValidation bool) http.Handler {
    reverseProxy := &httputil.ReverseProxy{
        Director: func(req *http.Request) {
            forwardedFOR := req.Header.Get(FORWARDED_FOR_HEADER)
            forwardedURL := req.Header.Get(CF_FORWARDED_URL_HEADER)
            sigHeader := req.Header.Get(CF_PROXY_SIGNATURE_HEADER)

            var body []byte
            var err error
            if req.Body != nil {
                body, err = ioutil.ReadAll(req.Body)
                if err != nil {
                    log.Fatalln(err.Error())
                }
                req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
            }
            logRequest(forwardedFOR, forwardedURL, sigHeader, string(body), req.Header, skipSslValidation)

            err = sleep()
            if err != nil {
                log.Fatalln(err.Error())
            }

            // Note that url.Parse is decoding any url-encoded characters.
            url, err := url.Parse(forwardedURL)
            if err != nil {
                log.Fatalln(err.Error())
            }

            req.URL = url
            req.Host = url.Host
        },
        Transport: transport,
    }
    return reverseProxy
}

func logRequest(forwardedFOR, forwardedURL, sigHeader, body string, headers http.Header, skipSslValidation bool) {
    log.Printf("Skip ssl validation set to %t", skipSslValidation)
    log.Println("Received request: ")
    log.Printf("%s: %s\n", FORWARDED_FOR_HEADER, forwardedFOR)
    log.Printf("%s: %s\n", CF_FORWARDED_URL_HEADER, forwardedURL)
    log.Printf("%s: %s\n", CF_PROXY_SIGNATURE_HEADER, sigHeader)
    log.Println("")
    log.Printf("Headers: %#v\n", headers)
    log.Println("")
    log.Printf("Request Body: %s\n", body)
}

type LoggingRoundTripper struct {
    transport http.RoundTripper
    limit []string
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

func NewLoggingRoundTripper(accessList []string, skipSslValidation bool) *LoggingRoundTripper {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: skipSslValidation},
    }
    return &LoggingRoundTripper{
        transport: tr,
        limit: accessList,
    }
}

func (lrt *LoggingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
    var err error
    var res *http.Response
    
    forwardedFOR := request.Header.Get(FORWARDED_FOR_HEADER)
    remoteIP := strings.Split(forwardedFOR, ", ")[0]

    log.Println("")
    log.Printf("Remote Address: %#v\n", remoteIP)
    
    if (len(lrt.limit) > 0) && (!contains(lrt.limit, remoteIP)) {
        log.Println("")
        log.Printf("Denying request for [%s]\n", remoteIP)
        resp := &http.Response{
            StatusCode: 403,
            Body:       ioutil.NopCloser(bytes.NewBufferString("Forbidden")),
        }
        return resp, nil
    }
    
    log.Printf("Forwarding to: %s\n", request.URL.String())
    res, err = lrt.transport.RoundTrip(request)
    if err != nil {
        return nil, err
    }

    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        log.Fatalln(err.Error())
    }
    log.Println("")
    log.Printf("Response Headers: %#v\n", res.Header)
    log.Println("")
    log.Printf("Response Body: %s\n", string(body))
    log.Println("")
    res.Body = ioutil.NopCloser(bytes.NewBuffer(body))

    log.Println("Sending response to GoRouter...")

    return res, err
}

func sleep() error {
    sleepMilliString := os.Getenv("ROUTE_SERVICE_SLEEP_MILLI")
    if sleepMilliString != "" {
        sleepMilli, err := strconv.ParseInt(sleepMilliString, 0, 64)
        if err != nil {
            return err
        }

        log.Printf("Sleeping for %d milliseconds\n", sleepMilli)
        time.Sleep(time.Duration(sleepMilli) * time.Millisecond)

    }
    return nil
}
