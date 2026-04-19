package resp

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Type constants
const (
	TypeSimpleString = '+'
	TypeError        = '-'
	TypeInteger      = ':'
	TypeBulkString   = '$'
	TypeArray        = '*'
)

// Command represents a parsed RESP command
type Command struct {
	Name string
	Args [][]byte
}

// Parser reads RESP protocol from a reader
type Parser struct {
	r *bufio.Reader
}

func NewParser(r io.Reader) *Parser {
	return &Parser{r: bufio.NewReaderSize(r, 4096)}
}

// ReadCommand reads the next command from the stream
func (p *Parser) ReadCommand() (*Command, error) {
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}

	if len(line) == 0 {
		return nil, fmt.Errorf("empty line")
	}

	switch line[0] {
	case TypeArray:
		return p.readArray(line)
	default:
		// Inline command (e.g. PING\r\n)
		return p.readInline(string(line))
	}
}

func (p *Parser) readArray(line []byte) (*Command, error) {
	count, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return nil, fmt.Errorf("invalid array length: %w", err)
	}
	if count <= 0 {
		return nil, fmt.Errorf("empty array")
	}

	args := make([][]byte, count)
	for i := 0; i < count; i++ {
		arg, err := p.readBulkString()
		if err != nil {
			return nil, err
		}
		args[i] = arg
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("no command name")
	}

	return &Command{
		Name: strings.ToUpper(string(args[0])),
		Args: args[1:],
	}, nil
}

func (p *Parser) readBulkString() ([]byte, error) {
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}
	if line[0] != TypeBulkString {
		return nil, fmt.Errorf("expected bulk string, got %c", line[0])
	}
	length, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return nil, fmt.Errorf("invalid bulk string length: %w", err)
	}
	if length == -1 {
		return nil, nil // null bulk string
	}

	buf := make([]byte, length+2) // +2 for \r\n
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return nil, err
	}
	return buf[:length], nil
}

func (p *Parser) readInline(line string) (*Command, error) {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty inline command")
	}
	args := make([][]byte, len(parts)-1)
	for i, part := range parts[1:] {
		args[i] = []byte(part)
	}
	return &Command{Name: strings.ToUpper(parts[0]), Args: args}, nil
}

func (p *Parser) readLine() ([]byte, error) {
	line, err := p.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	// Strip \r\n
	if len(line) >= 2 && line[len(line)-2] == '\r' {
		return line[:len(line)-2], nil
	}
	return line[:len(line)-1], nil
}

// Writer writes RESP protocol responses
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) WriteSimpleString(s string) error {
	_, err := fmt.Fprintf(w.w, "+%s\r\n", s)
	return err
}

func (w *Writer) WriteError(msg string) error {
	_, err := fmt.Fprintf(w.w, "-ERR %s\r\n", msg)
	return err
}

func (w *Writer) WriteInteger(n int64) error {
	_, err := fmt.Fprintf(w.w, ":%d\r\n", n)
	return err
}

func (w *Writer) WriteBulkString(b []byte) error {
	if b == nil {
		_, err := fmt.Fprint(w.w, "$-1\r\n")
		return err
	}
	_, err := fmt.Fprintf(w.w, "$%d\r\n", len(b))
	if err != nil {
		return err
	}
	_, err = w.w.Write(b)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w.w, "\r\n")
	return err
}

func (w *Writer) WriteNull() error {
	_, err := fmt.Fprint(w.w, "$-1\r\n")
	return err
}

func (w *Writer) WriteOK() error {
	return w.WriteSimpleString("OK")
}

func (w *Writer) WriteArray(items [][]byte) error {
	_, err := fmt.Fprintf(w.w, "*%d\r\n", len(items))
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := w.WriteBulkString(item); err != nil {
			return err
		}
	}
	return nil
}
