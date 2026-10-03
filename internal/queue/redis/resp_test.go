package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// respCommander is a test-only RESP2 client. The production adapter requires an
// injected Commander; this fixture does not choose a production Redis library,
// connection policy, deployment, TLS policy, or credential source.
type respCommander struct{ address, username, password string }

func realCommander(t *testing.T) *respCommander {
	t.Helper()
	address := os.Getenv("CYB15_TEST_REDIS_ADDRESS")
	if address == "" {
		t.Skip("CYB15_TEST_REDIS_ADDRESS is not configured")
	}
	return &respCommander{address: address}
}

func (r *respCommander) Do(ctx context.Context, args ...any) (any, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	if r.username != "" {
		if err := writeRESP(conn, []any{"AUTH", r.username, r.password}); err != nil {
			return nil, err
		}
		response, err := readRESP(reader, 0)
		if err != nil || response != "OK" {
			return nil, errors.New("test Redis authentication failed")
		}
	}
	if err := writeRESP(conn, args); err != nil {
		return nil, err
	}
	return readRESP(reader, 0)
}

func writeRESP(writer io.Writer, args []any) error {
	var request strings.Builder
	fmt.Fprintf(&request, "*%d\r\n", len(args))
	for _, arg := range args {
		value := fmt.Sprint(arg)
		fmt.Fprintf(&request, "$%d\r\n%s\r\n", len(value), value)
	}
	_, err := io.WriteString(writer, request.String())
	return err
}

func readRESP(reader *bufio.Reader, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("invalid test RESP nesting")
	}
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 3 || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("invalid test RESP response")
	}
	value := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return value, nil
	case '-':
		return nil, errors.New(value)
	case ':':
		return strconv.ParseInt(value, 10, 64)
	case '$':
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < -1 || n > 1<<20 {
			return nil, errors.New("invalid test RESP bulk length")
		}
		if n == -1 {
			return nil, nil
		}
		data := make([]byte, int(n)+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		if string(data[n:]) != "\r\n" {
			return nil, errors.New("invalid test RESP bulk terminator")
		}
		return string(data[:n]), nil
	case '*':
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < -1 || n > 4096 {
			return nil, errors.New("invalid test RESP array length")
		}
		if n == -1 {
			return nil, nil
		}
		items := make([]any, int(n))
		for i := range items {
			items[i], err = readRESP(reader, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return items, nil
	default:
		return nil, errors.New("invalid test RESP type")
	}
}
