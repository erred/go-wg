package wg

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"
)

var wg = "wg"

// Interface is a Wireguard interface
type Interface struct {
	ListenPort int
	FwMark     string
	PrivateKey string

	// Show only
	PublicKey string
}

// Bytes encodes an Interface Section in a conf file
func (i Interface) Bytes() []byte {
	buf := bytes.NewBufferString("[Interface]\n")
	if i.ListenPort != 0 {
		buf.WriteString("ListenPort = " + strconv.Itoa(i.ListenPort) + "\n")
	}
	if i.FwMark != "" {
		buf.WriteString("FwMark = " + i.FwMark + "\n")
	}
	if i.PrivateKey != "" {
		buf.WriteString("PrivateKey = " + i.PrivateKey + "\n")
	}
	buf.WriteString("\n")
	return buf.Bytes()
}

// Peer is a Wireguard peer
type Peer struct {
	PublicKey           string
	Endpoint            string   // host:port
	AllowedIPs          []string // ip/mask
	PresharedKey        string
	PersistentKeepalive int

	// Show only
	LatestHandshake time.Duration
	// Transfer
	Received int64
	Sent     int64
}

// Bytes encodes a Peer section in a conf file
// Ignores values not used in a conf
func (p Peer) Bytes() []byte {
	buf := bytes.NewBufferString("[Peer]\n")
	if p.PublicKey != "" {
		buf.WriteString("PublicKey = " + p.PublicKey + "\n")
	}
	if p.Endpoint != "" {
		buf.WriteString("Endpint = " + p.Endpoint + "\n")
	}
	if len(p.AllowedIPs) != 0 {
		buf.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ",") + "\n")
	}
	if p.PresharedKey != "" {
		buf.WriteString("PresharedKey = " + p.PresharedKey + "\n")
	}
	return buf.Bytes()
}

// Conf represents a Wireguard interface configuration
type Conf struct {
	Interface
	Peers []Peer
}

// NewConfBytes decodes bytes into a conf
func NewConfBytes(bb []byte) (*Conf, error) {
	var err error
	var c = &Conf{}
	var p int

	lines := strings.Split(string(bb), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		words := strings.SplitN(line, " ", 3)
		switch {

		// Interface
		case strings.Contains(line, "Interface"):
			// nop
		case strings.Contains(line, "ListenPort"):
			c.Interface.ListenPort, err = strconv.Atoi(words[2])
			if err != nil {
				return c, fmt.Errorf("error parsing ListenPort: %v", err)
			}
		case strings.Contains(line, "FwMark"):
			c.Interface.FwMark = words[2]
		case strings.Contains(line, "PrivateKey"):
			c.Interface.PrivateKey = words[2]

		// Peer
		case strings.Contains(line, "Peer"):
			c.Peers = append(c.Peers)
			p = len(c.Peers)
		case strings.Contains(line, "PublicKey"):
			c.Peers[p].PublicKey = words[2]
		case strings.Contains(line, "Endpoint"):
			c.Peers[p].Endpoint = words[2]
		case strings.Contains(line, "AllowedIPs"):
			for _, ip := range strings.Split(words[2], ",") {
				c.Peers[p].AllowedIPs = append(c.Peers[p].AllowedIPs, strings.TrimSpace(ip))
			}
		case strings.Contains(line, "PresharedKey"):
			c.Peers[p].PresharedKey = words[2]
		case strings.Contains(line, "PersistentKeepalive"):
			c.Peers[p].PersistentKeepalive, err = strconv.Atoi(words[2])
			if err != nil {
				return c, fmt.Errorf("error parsing PersistentKeepalive: %v", err)
			}

		// Ignore empty lines
		case line == "":
			// nop
		// Unknown key
		default:
			return c, fmt.Errorf("unkown key: %v", line)
		}
	}
	return c, nil
}

// Bytes eencodes a Conf
func (c Conf) Bytes() []byte {
	buf := bytes.NewBuffer(c.Interface.Bytes())
	for _, p := range c.Peers {
		buf.Write(p.Bytes())
	}
	return buf.Bytes()
}

func Show() {
	// TODO
}

// ShowConf shows conf for an interface
// wg showconf iface
func ShowConf(iface string) (*Conf, error) {
	return ShowConfCtx(context.Background(), iface)
}

// ShowConfCtx shows conf for an interface
// ctx for process management
// wg showconf iface
func ShowConfCtx(ctx context.Context, iface string) (*Conf, error) {
	b, err := exec.CommandContext(ctx, wg, "showconf", iface).Output()
	if err != nil {
		return nil, fmt.Errorf("showconf: %v", err)
	}
	c, err := NewConfBytes(b)
	if err != nil {
		err = fmt.Errorf("parse showconf: %v", err)
	}
	return c, err
}

func Set() {
	// TODO
}

// SetConf set a conf struct
// **write conf to fpath**
// wg addconf iface fpath
// rm fpath
func SetConf(iface string, conf Conf) error {
	return SetConfCtx(context.Background(), iface, conf)
}

// SetConfCtx set a conf struct
// ctx for process management
// **write conf to fpath**
// wg addconf iface fpath
// rm fpath
func SetConfCtx(ctx context.Context, iface string, conf Conf) error {
	fname, err := tmpConf(conf)
	if err != nil {
		return fmt.Errorf("write temp conf: %v", err)
	}
	defer os.RemoveAll(path.Dir(fname))

	return SetConfFileCtx(ctx, iface, fname)
}

// SetConfFile set a conf file
// ctx for process management
// wg setconf iface fpath
func SetConfFile(iface, fpath string) error {
	return SetConfFileCtx(context.Background(), iface, fpath)
}

// SetConfFileCtx set a conf file
// ctx for process management
// wg setconf iface fpath
func SetConfFileCtx(ctx context.Context, iface, fpath string) error {
	err := exec.CommandContext(ctx, wg, "setconf", iface, fpath).Run()
	if err != nil {
		err = fmt.Errorf("setconffile: %v", err)
	}
	return err
}

// AddConf add a conf struct
// **write conf to fpath**
// wg addconf iface fpath
// rm fpath
func AddConf(iface string, conf Conf) error {
	return AddConfCtx(context.Background(), iface, conf)
}

// AddConfCtx add a conf struct
// ctx for process management
// **write conf to fpath**
// wg addconf iface fpath
// rm fpath
func AddConfCtx(ctx context.Context, iface string, conf Conf) error {
	fname, err := tmpConf(conf)
	if err != nil {
		return fmt.Errorf("write temp conf: %v", err)
	}
	defer os.RemoveAll(path.Dir(fname))

	return AddConfFileCtx(ctx, iface, fname)
}

// AddConfFile add a conf file
// wg addconf iface fpath
func AddConfFile(iface, fpath string) error {
	return AddConfFileCtx(context.Background(), iface, fpath)
}

// AddConfFileCtx add a conf file
// ctx for process management
// wg addconf iface fpath
func AddConfFileCtx(ctx context.Context, iface, fpath string) error {
	err := exec.CommandContext(ctx, wg, "addconf", iface, fpath).Run()
	if err != nil {
		err = fmt.Errorf("addconffile: ", err)
	}
	return err
}

// GenKey generates a private key
// wg genkey
func GenKey() ([]byte, error) {
	return GenKeyCtx(context.Background())
}

// GenKeyCtx generates a private key
// ctx for process management
// wg genkey
func GenKeyCtx(ctx context.Context) ([]byte, error) {
	b, err := exec.CommandContext(ctx, wg, "genkey").Output()
	if err != nil {
		err = fmt.Errorf("genkey: %v", err)
	}
	return b, err
}

// GenPsk generates a preshared key
// wg genpsk
func GenPsk() ([]byte, error) {
	return GenPskCtx(context.Background())
}

// GenPskCtx generates a preshared key
// ctx for process management
// wg genpsk
func GenPskCtx(ctx context.Context) ([]byte, error) {
	b, err := exec.CommandContext(ctx, wg, "genpsk").Output()
	if err != nil {
		err = fmt.Errorf("genpsk: %v", err)
	}
	return b, err
}

// PubKey generaetes a public key from a private key
// echo $privkey | wg pubkey
func PubKey(privKey []byte) ([]byte, error) {
	return PubKeyCtx(context.Background(), privKey)
}

// PubKeyCtx generaetes a public key from a private key
// ctx for process management
// echo $privkey | wg pubkey
func PubKeyCtx(ctx context.Context, privKey []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, wg, "pubkey")
	cmd.Stdin = bytes.NewBuffer(privKey)
	b, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("pubkey: %v", err)
	}
	return b, err
}

// tmpConf writes a conf to a temp file
// returns filename, error
func tmpConf(conf Conf) (string, error) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		return "", fmt.Errorf("create temp dir error: %v", err)
	}
	fname := path.Join(d, "wg.conf")
	err = ioutil.WriteFile(fname, conf.Bytes(), 0600)
	if err != nil {
		return "", fmt.Errorf("write temp file error: %v", err)
	}
	return fname, nil
}
