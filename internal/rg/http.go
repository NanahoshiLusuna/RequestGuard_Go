package rg

import (
	"bytes"
	"strconv"
	"strings"
)

var hopByHop = map[string]struct{}{
	"connection": {}, "keep-alive": {}, "proxy-authenticate": {}, "proxy-authorization": {},
	"te": {}, "trailers": {}, "transfer-encoding": {}, "upgrade": {},
	"proxy-connection": {}, "content-length": {},
}

type RequestError struct {
	Code   string
	Ban    bool
	Status int
}

func (e *RequestError) Error() string { return e.Code }

var errClientClosed = &RequestError{Code: "closed", Ban: false, Status: 400}

func IsClosed(err error) bool {
	re, ok := err.(*RequestError)
	return ok && re == errClientClosed
}

type Header struct {
	Name  string
	Value string
}

type ParsedRequest struct {
	Method  string
	Target  string
	Version string
	Headers []Header
	Body    []byte
}

func (p ParsedRequest) HeaderValues(name string) []string {
	var out []string
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

type byteReader interface {
	Read(p []byte) (int, error)
}

func ParseRequestBytes(data []byte, cfg Config) (ParsedRequest, error) {
	return ReadRequest(bytes.NewReader(data), cfg)
}

func ReadRequest(r byteReader, cfg Config) (ParsedRequest, error) {
	parsed, rest, err := ReadHead(r, cfg)
	if err != nil {
		return ParsedRequest{}, err
	}
	body, err := ReadBody(r, parsed, rest, cfg)
	if err != nil {
		return ParsedRequest{}, err
	}
	parsed.Body = body
	return parsed, nil
}

func ReadHead(r byteReader, cfg Config) (ParsedRequest, []byte, error) {
	buf := make([]byte, 0, 1024)
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		if bytes.Contains(buf, []byte("\n\n")) && !bytes.Contains(buf, []byte("\r")) {
			return ParsedRequest{}, nil, &RequestError{"lf_only", false, 400}
		}
		next, err := readChunk(r, 4096)
		if err != nil {
			if len(buf) == 0 {
				return ParsedRequest{}, nil, errClientClosed
			}
			if bytes.Contains(buf, []byte{0}) {
				return ParsedRequest{}, nil, &RequestError{"nul", true, 400}
			}
			return ParsedRequest{}, nil, &RequestError{"truncated", false, 400}
		}
		buf = append(buf, next...)
		if bytes.Contains(buf, []byte("\r\n\r\n")) {
			break
		}
		if bytes.Contains(buf, []byte{0}) {
			return ParsedRequest{}, nil, &RequestError{"nul", true, 400}
		}
		if len(buf) > cfg.MaxHeaderBytes {
			return ParsedRequest{}, nil, &RequestError{"headers_too_large", true, 431}
		}
	}
	head, rest, _ := bytes.Cut(buf, []byte("\r\n\r\n"))
	if bytes.Contains(head, []byte{0}) {
		return ParsedRequest{}, nil, &RequestError{"nul", true, 400}
	}
	if len(head) > cfg.MaxHeaderBytes {
		return ParsedRequest{}, nil, &RequestError{"headers_too_large", true, 431}
	}
	parsed, err := parseHead(head, cfg)
	return parsed, rest, err
}

func ReadBody(r byteReader, parsed ParsedRequest, rest []byte, cfg Config) ([]byte, error) {
	if len(parsed.HeaderValues("transfer-encoding")) > 0 {
		return readChunked(r, rest, cfg.MaxBodyBytes)
	}
	lengths := parsed.HeaderValues("content-length")
	if len(lengths) == 0 {
		return []byte{}, nil
	}
	length, err := contentLength(lengths[0], cfg)
	if err != nil {
		return nil, err
	}
	buf := append([]byte{}, rest...)
	for len(buf) < length {
		need := length - len(buf)
		if need > 65536 {
			need = 65536
		}
		next, err := readChunk(r, need)
		if err != nil {
			return nil, &RequestError{"truncated_body", false, 400}
		}
		buf = append(buf, next...)
	}
	return buf[:length], nil
}

func readChunk(r byteReader, size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := r.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, ioUnexpected()
}

func ioUnexpected() error { return errClientClosed }

func parseHead(head []byte, cfg Config) (ParsedRequest, error) {
	text := latin1(head)
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return ParsedRequest{}, &RequestError{"bad_request_line", true, 400}
	}
	if latinLen(lines[0]) > cfg.MaxHeaderLine {
		return ParsedRequest{}, &RequestError{"line_too_long", true, 400}
	}
	for _, line := range lines[1:] {
		if latinLen(line) > cfg.MaxHeaderLine {
			return ParsedRequest{}, &RequestError{"line_too_long", true, 400}
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return ParsedRequest{}, &RequestError{"header_fold", true, 400}
		}
	}
	method, target, version, err := requestLine(lines[0])
	if err != nil {
		return ParsedRequest{}, err
	}
	if len(lines)-1 > cfg.MaxHeaders {
		return ParsedRequest{}, &RequestError{"too_many_headers", true, 431}
	}
	var headers []Header
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !headerName(name) {
			return ParsedRequest{}, &RequestError{"bad_header", true, 400}
		}
		for _, r := range value {
			if (r < 0x20 && r != '\t') || r == 0x7f {
				return ParsedRequest{}, &RequestError{"control_char", true, 400}
			}
		}
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		value = strings.TrimRight(value, " \t")
		headers = append(headers, Header{Name: name, Value: value})
	}
	parsed := ParsedRequest{Method: method, Target: target, Version: version, Headers: headers}
	if err := rejectHostile(&parsed, cfg); err != nil {
		return ParsedRequest{}, err
	}
	return parsed, nil
}

func requestLine(line string) (string, string, string, error) {
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return "", "", "", &RequestError{"bad_request_line", true, 400}
	}
	for _, part := range parts {
		if part == "" {
			return "", "", "", &RequestError{"bad_request_line", true, 400}
		}
	}
	method, target, version := parts[0], parts[1], parts[2]
	if !methodToken(method) {
		return "", "", "", &RequestError{"bad_method", true, 400}
	}
	if version != "HTTP/1.0" && version != "HTTP/1.1" {
		if len(version) == 8 && strings.HasPrefix(version, "HTTP/") && version[5] >= '0' && version[5] <= '9' && version[6] == '.' && version[7] >= '0' && version[7] <= '9' {
			return "", "", "", &RequestError{"unsupported_version", false, 505}
		}
		return "", "", "", &RequestError{"bad_version", true, 400}
	}
	return method, target, version, nil
}

func rejectHostile(parsed *ParsedRequest, cfg Config) error {
	if parsed.Method == "CONNECT" {
		return &RequestError{"connect", true, 405}
	}
	if latinLen(parsed.Target) > cfg.MaxTargetBytes {
		return &RequestError{"target_too_long", true, 414}
	}
	target := parsed.Target
	switch {
	case parsed.Method == "OPTIONS" && target == "*":
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		return &RequestError{"absolute_form", true, 400}
	case !strings.HasPrefix(target, "/"):
		return &RequestError{"bad_target", true, 400}
	default:
		if strings.Contains(target, `\`) {
			return &RequestError{"backslash", true, 400}
		}
		if err := inspectTarget(target, cfg.MaxDotDot); err != nil {
			return err
		}
	}
	hosts := parsed.HeaderValues("host")
	if len(hosts) > 1 {
		return &RequestError{"duplicate_host", true, 400}
	}
	if parsed.Version == "HTTP/1.1" && len(hosts) == 0 {
		return &RequestError{"missing_host", false, 400}
	}
	lengths := parsed.HeaderValues("content-length")
	codings := parsed.HeaderValues("transfer-encoding")
	if len(lengths) > 0 && len(codings) > 0 {
		return &RequestError{"cl_te", true, 400}
	}
	if len(lengths) > 1 {
		return &RequestError{"duplicate_cl", true, 400}
	}
	if len(lengths) == 1 {
		if _, err := contentLength(lengths[0], cfg); err != nil {
			return err
		}
	}
	if len(codings) > 0 {
		var found []string
		for _, raw := range codings {
			for _, part := range strings.Split(raw, ",") {
				coding := strings.ToLower(strings.TrimSpace(strings.Split(part, ";")[0]))
				if coding != "" {
					found = append(found, coding)
				}
			}
		}
		if len(found) != 1 || found[0] != "chunked" {
			return &RequestError{"bad_transfer_encoding", true, 400}
		}
	}
	return nil
}

func contentLength(raw string, cfg Config) (int, error) {
	text := strings.TrimSpace(raw)
	if len(text) > 10 || text == "" || !digits(text) {
		return 0, &RequestError{"bad_content_length", true, 400}
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, &RequestError{"bad_content_length", true, 400}
	}
	if n > cfg.AbsurdBodyBytes {
		return 0, &RequestError{"absurd_body", true, 413}
	}
	if n > cfg.MaxBodyBytes {
		return 0, &RequestError{"body_too_large", false, 413}
	}
	return n, nil
}

func inspectTarget(target string, maxDotDot int) error {
	raw := []byte(target)
	decoded := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '%' {
			if i+3 > len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return &RequestError{"bad_percent", true, 400}
			}
			value, _ := strconv.ParseInt(string(raw[i+1:i+3]), 16, 0)
			if value == 0 {
				return &RequestError{"encoded_nul", true, 400}
			}
			decoded = append(decoded, byte(value))
			i += 3
			continue
		}
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return &RequestError{"control_char", true, 400}
		}
		decoded = append(decoded, raw[i])
		i++
	}
	path := string(decoded)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	count := 0
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			count++
		}
	}
	if count > maxDotDot {
		return &RequestError{"traversal", true, 400}
	}
	return nil
}

func readChunked(r byteReader, rest []byte, maxBody int) ([]byte, error) {
	buf := append([]byte{}, rest...)
	var body []byte
	ceiling := maxBody + 8192
	for {
		line, err := readLine(&buf, r, 4096)
		if err != nil {
			return nil, err
		}
		token := bytes.TrimSpace(bytes.SplitN(line, []byte(";"), 2)[0])
		if len(token) == 0 || !hexBytes(token) {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		size, err := strconv.ParseInt(string(token), 16, 64)
		if err != nil {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		if size == 0 {
			for {
				trailer, err := readLine(&buf, r, 8192)
				if err != nil {
					return nil, err
				}
				if len(trailer) == 0 {
					return body, nil
				}
			}
		}
		if int64(len(body))+size > int64(maxBody) {
			return nil, &RequestError{"body_too_large", false, 413}
		}
		data, err := readExact(&buf, r, int(size)+2, ceiling)
		if err != nil {
			return nil, err
		}
		if !bytes.HasSuffix(data, []byte("\r\n")) {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		body = append(body, data[:len(data)-2]...)
	}
}

func readLine(buf *[]byte, r byteReader, limit int) ([]byte, error) {
	for !bytes.Contains(*buf, []byte("\r\n")) {
		if len(*buf) > limit {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		next, err := readChunk(r, 4096)
		if err != nil {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		*buf = append(*buf, next...)
	}
	parts := bytes.SplitN(*buf, []byte("\r\n"), 2)
	if len(parts) != 2 {
		return nil, &RequestError{"bad_chunk", true, 400}
	}
	if len(parts[0]) > limit {
		return nil, &RequestError{"bad_chunk", true, 400}
	}
	*buf = append([]byte{}, parts[1]...)
	return parts[0], nil
}

func readExact(buf *[]byte, r byteReader, size, ceiling int) ([]byte, error) {
	for len(*buf) < size {
		need := size - len(*buf)
		if need > 65536 {
			need = 65536
		}
		next, err := readChunk(r, need)
		if err != nil {
			return nil, &RequestError{"bad_chunk", true, 400}
		}
		*buf = append(*buf, next...)
		if len(*buf) > ceiling {
			return nil, &RequestError{"absurd_body", true, 413}
		}
	}
	got := append([]byte{}, (*buf)[:size]...)
	*buf = append([]byte{}, (*buf)[size:]...)
	return got, nil
}

func init() {}

func latin1(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

func latinLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func methodToken(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	return headerName(s)
}

func headerName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

func digits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexBytes(b []byte) bool {
	for _, c := range b {
		if !isHex(c) {
			return false
		}
	}
	return true
}
