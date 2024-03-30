package main

import (
    "bufio"
    "crypto/tls"
    "crypto/x509"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

/* result of processing a domain name */
type procResult struct {
    addr  string
    names []string
    org   string // Added organization name
    err   error
}

// run parameters (filled from CLI arguments)
var (
    verbose              bool
    concurrency          int
    defaultPorts         []string
    timeout              int
    onlyValidDomainNames bool
    orgEnabled           bool // Added organization flag
)

var usage = "" +
    `usage: cero [options] [targets]
if [targets] not provided in commandline arguments, will read from stdin
`

func main() {
    // parse CLI arguments
    var ports string

    flag.BoolVar(&verbose, "v", false, `Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'`)
    flag.IntVar(&concurrency, "c", 100, "Concurrency level")
    flag.StringVar(&ports, "p", "443", "TLS ports to use, if not specified explicitly in host address. Use comma-separated list")
    flag.IntVar(&timeout, "t", 4, "TLS Connection timeout in seconds")
    flag.BoolVar(&onlyValidDomainNames, "d", false, "Output only valid domain names (e.g. strip IPs, wildcard domains and gibberish)")
    flag.BoolVar(&orgEnabled, "org", false, "Display organization name") // Added organization flag

    // set custom usage text
    flag.Usage = func() {
        fmt.Fprintln(os.Stderr, usage)
        fmt.Fprintln(os.Stderr, "options:")
        flag.PrintDefaults()
    }

    flag.Parse()

    // parse default port list into string slice
    defaultPorts = strings.Split(ports, `,`)

    // channels
    chanInput := make(chan string)
    chanResult := make(chan *procResult)

    // a common dialer
    dialer := &net.Dialer{
        Timeout: time.Duration(timeout) * time.Second,
    }

    // create and start concurrent workers
    var workersWG sync.WaitGroup
    for i := 0; i < concurrency; i++ {
        workersWG.Add(1)
        go func() {
            for addr := range chanInput {
                result := &procResult{addr: addr}
                result.names, result.org, result.err = grabCert(addr, dialer, onlyValidDomainNames, orgEnabled) // Modified to also return organization name
                chanResult <- result
            }
            workersWG.Done()
        }()
    }

    // close result channel when workers are done
    go func() {
        workersWG.Wait()
        close(chanResult)
    }()

    // create and start result-processing worker
    var outputWG sync.WaitGroup
    outputWG.Add(1)
    go func() {
        for result := range chanResult {
            // in verbose mode, print all errors and results, with corresponding input values
            if verbose {
                if result.err != nil {
                    fmt.Fprintf(os.Stderr, "%s -- %s\n", result.addr, result.err)
                } else {
                    fmt.Fprintf(os.Stdout, "%s -- %s [%s]\n", result.addr, result.names, result.org) // Modified output format to include organization name
                }
            } else {
                // non-verbose: just print scraped names, one at line
                for _, name := range result.names {
                    fmt.Fprintf(os.Stdout, "%s [%s]\n", name, result.org) // Modified output format to include organization name
                }
            }
        }
        outputWG.Done()
    }()

    // consume output to start things moving
    if len(flag.Args()) > 0 {
        for _, addr := range flag.Args() {
            processInputItem(addr, chanInput, chanResult)
        }
    } else {
        // every line of stdin is considered as a input
        sc := bufio.NewScanner(os.Stdin)
        for sc.Scan() {
            addr := strings.TrimSpace(sc.Text())
            processInputItem(addr, chanInput, chanResult)
        }
    }

    // close input channel when input fully consumed
    close(chanInput)

    // wait for processing to finish
    outputWG.Wait()
}

// process input item
// if orrors occur during parsing, they are pushed straight to result channel
func processInputItem(input string, chanInput chan string, chanResult chan *procResult) {
    // initial inputs are skipped
    input = strings.TrimSpace(input)
    if input == "" {
        return
    }

    // split input to host and port (if specified)
    host, port := splitHostPort(input)

    // get ports list to use
    var ports []string
    if port == "" {
        // use ports from default list if not specified explicitly
        ports = defaultPorts
    } else {
        ports = []string{port}
    }

    // CIDR?
    if isCIDR(host) {
        // expand CIDR
        ips, err := expandCIDR(host)
        if err != nil {
            chanResult <- &procResult{addr: input, err: err}
            return
        }

        // feed IPs from CIDR to input channel
        for _, ip := range ips {
            for _, port := range ports {
                chanInput <- net.JoinHostPort(ip, port)
            }
        }
    } else {
        // feed atomic host to input channel
        for _, port := range ports {
            chanInput <- net.JoinHostPort(host, port)
        }
    }
}

/* connects to addr and grabs certificate information.
returns slice of domain names from grabbed certificate */
func grabCert(addr string, dialer *net.Dialer, onlyValidDomainNames bool, orgEnabled bool) ([]string, string, error) { // Modified to return organization name
    // dial
    conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        return nil, "", err
    }
    defer conn.Close()

    // get first certificate in chain
    cert := conn.ConnectionState().PeerCertificates[0]

    // get CommonName and all SANs into a slice
    names := make([]string, 0, len(cert.DNSNames)+1)
    if onlyValidDomainNames && isDomainName(cert.Subject.CommonName) || !onlyValidDomainNames {
        names = append(names, cert.Subject.CommonName)
    }

    // append all SANs, excluding one that is equal to CN (if any)
    for _, name := range cert.DNSNames {
        if name != cert.Subject.CommonName {
            if onlyValidDomainNames && isDomainName(name) || !onlyValidDomainNames {
                names = append(names, name)
            }
        }
    }

    var orgName string
    if orgEnabled { // Extract organization name if enabled
        orgName = getOrganizationName(cert)
    }

    return names, orgName, nil
}

// getOrganizationName extracts the organization name from the SSL certificate
func getOrganizationName(cert *x509.Certificate) string {
    if len(cert.Subject.Organization) > 0 {
        return cert.Subject.Organization[0]
    }
    return ""
}

// splitHostPort splits a string into host and port
func splitHostPort(addr string) (string, string) {
    parts := strings.SplitN(addr, ":", 2)
    if len(parts) == 2 {
        return parts[0], parts[1]
    }
    return addr, ""
}

// isCIDR checks if the given address is in CIDR notation
func isCIDR(addr string) bool {
    _, _, err := net.ParseCIDR(addr)
    return err == nil
}

// expandCIDR expands the given CIDR address to individual IP addresses
func expandCIDR(addr string) ([]string, error) {
    ips := make([]string, 0)
    ip, ipnet, err := net.ParseCIDR(addr)
    if err != nil {
        return nil, err
    }
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    // Remove network address and broadcast address
    return ips[1 : len(ips)-1], nil
}

// inc increments the IP address
func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

// isDomainName checks if the given string is a valid domain name
func isDomainName(name string) bool {
    parts := strings.Split(name, ".")
    if len(parts) < 2 {
        return false
    }
    for _, part := range parts {
        if part == "" {
            return false
        }
    }
    return true
}

