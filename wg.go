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
	PresharedKey        string
	AllowedIPs          []string // ip/mask
	Endpoint            string   // host:port
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
	if p.PresharedKey != "" {
		buf.WriteString("PresharedKey = " + p.PresharedKey + "\n")
	}
	if len(p.AllowedIPs) != 0 {
		buf.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ",") + "\n")
	}
	if p.Endpoint != "" {
		buf.WriteString("Endpint = " + p.Endpoint + "\n")
	}
	if p.PersistentKeepalive != 0 {
		buf.WriteString("PersistentKeepalive = " + strconv.Itoa(p.PersistentKeepalive) + "\n")
	}
	buf.WriteString("\n")
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
		if line == "" {
			continue
		}
		words := strings.SplitN(line, " ", 3)
		switch words[0] {

		// Interface
		case "ListenPort":
			c.Interface.ListenPort, err = strconv.Atoi(words[2])
			if err != nil {
				return c, fmt.Errorf("error parsing ListenPort: %v", err)
			}
		case "FwMark":
			c.Interface.FwMark = words[2]
		case "PrivateKey":
			c.Interface.PrivateKey = words[2]

		// Peer
		case "[Peer]":
			c.Peers = append(c.Peers)
			p = len(c.Peers)
		case "PublicKey":
			c.Peers[p].PublicKey = words[2]
		case "Endpoint":
			c.Peers[p].Endpoint = words[2]
		case "AllowedIPs":
			for _, ip := range strings.Split(words[2], ",") {
				c.Peers[p].AllowedIPs = append(c.Peers[p].AllowedIPs, strings.TrimSpace(ip))
			}
		case "PresharedKey":
			c.Peers[p].PresharedKey = words[2]
		case "PersistentKeepalive":
			if words[2] == "off" {
				c.Peers[p].PersistentKeepalive = 0
			} else {
				c.Peers[p].PersistentKeepalive, err = strconv.Atoi(words[2])
				if err != nil {
					return c, fmt.Errorf("error parsing PersistentKeepalive: %v", err)
				}
			}

		// Unknown key
		default:
			return c, fmt.Errorf("unkown key: %v", line)
		}
	}
	return c, nil
}

// NewStatusBytes decodes bytes into a conf
func NewStatusBytes(bb []byte) (*Conf, error) {
	var err error
	var c = &Conf{}
	var p int

	lines := strings.Split(string(bb), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		words := strings.SplitN(line, ":", 2)
		switch words[0] {

		// Interface
		case "interface":
			// nop
		case "public key":
			c.Interface.PublicKey = strings.TrimSpace(words[1])
		case "private key":
			c.Interface.PrivateKey = strings.TrimSpace(words[1])
		case "listening port":
			c.Interface.ListenPort, err = strconv.Atoi(words[1])
			if err != nil {
				return c, fmt.Errorf("error parsing ListenPort: %v", err)
			}
		case "fwmark":
			c.Interface.FwMark = strings.TrimSpace(words[1])

		// Peer
		case "peer":
			c.Peers = append(c.Peers)
			p = len(c.Peers)
			c.Peers[p].PublicKey = strings.TrimSpace(words[1])
		case "endpoint":
			c.Peers[p].Endpoint = strings.TrimSpace(words[1])
		case "allowed ips":
			for _, ip := range strings.Split(words[1], ",") {
				c.Peers[p].AllowedIPs = append(c.Peers[p].AllowedIPs, strings.TrimSpace(ip))
			}
		case "preshared key":
			c.Peers[p].PresharedKey = words[1]
		case "transfer":
			var v = make([]float32, 2)
			var u = make([]string, 2)
			_, err := fmt.Sscanf(strings.TrimSpace(words[1]), "%f %s received, %f %s sent", &v[0], &u[0], &v[1], &u[1])
			if err != nil {
				return c, fmt.Errorf("error parsing transfer: %v", err)
			}
			for i, unit := range u {
				switch unit {
				case "B":
					// nop
				case "KiB":
					v[i] *= 1024
				case "MiB":
					v[i] *= 1024 * 1024
				case "GiB":
					v[i] *= 1024 * 1024 * 1024
				case "TiB":
					v[i] *= 1024 * 1024 * 1024 * 1024
				}
				switch i {
				case 0:
					c.Peers[p].Received = int64(v[i])
				case 1:
					c.Peers[p].Sent = int64(v[i])
				}
			}
		case "persistent keepalive":
			// TODO
		case "latest handshake":
			// TODO

		// Unknown key
		default:
			return c, fmt.Errorf("unknown key: %v", line)
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

// Show the current status of an interface
// wg show iface
func Show(iface string) (*Conf, error) {
	return ShowCtx(context.Background(), iface)
}

// ShowCtx the current status of an interface
// ctx for process management
// wg show iface
func ShowCtx(ctx context.Context, iface string) (*Conf, error) {
	cmd := exec.CommandContext(ctx, wg, "show", iface)
	cmd.Env = append(cmd.Env, "WG_HIDE_KEYS=never")
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("show: %v", err)
	}
	c, err := NewConfBytes(b)
	if err != nil {
		err = fmt.Errorf("decode showconf output error: %v", err)
	}
	return c, err
}

// ShowInterfaces lists all Wireguard interfaces
// wg show interfaces
func ShowInterfaces() ([]string, error) {
	return ShowInterfacesCtx(context.Background())
}

// ShowInterfacesCtx lists all Wireguard interfaces
// ctx for process management
// wg show interfaces
func ShowInterfacesCtx(ctx context.Context) ([]string, error) {
	b, err := exec.CommandContext(ctx, wg, "show", "interfaces").Output()
	if err != nil {
		return nil, fmt.Errorf("show interfaces: %v", err)
	}
	return strings.Split(string(b), " "), nil
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

// SetOptPeer are options for peers for Set (wg set ... peer ...)
// only PublicKey is mandatory
type SetOptPeer struct {
	PublicKey           string
	Remove              bool
	PskFpath            string
	Endpoint            string
	PersistentKeepalive *int // differentiate between unset and 0
	AllowedIPs          []string
}

// Args serializes opts to cli args
func (o SetOptPeer) Args() []string {
	args := []string{"peer", o.PublicKey}
	if o.Remove {
		return append(args, "remove")
	}
	if o.PskFpath != "" {
		args = append(args, "preshared-key", o.PskFpath)
	}
	if o.Endpoint != "" {
		args = append(args, "endpoint", o.Endpoint)
	}
	if o.PersistentKeepalive != nil {
		args = append(args, "persistent-keepalive", strconv.Itoa(*o.PersistentKeepalive))
	}
	if len(o.AllowedIPs) != 0 {
		args = append(args, "allowed-ips", strings.Join(o.AllowedIPs, ","))
	}
	return args
}

// SetOpt are options for Set (wg set)
// Only Interface is mandatory
type SetOpt struct {
	Interface    string
	ListenPort   int
	FwMark       string
	PrivKeyFpath string
	Peers        []SetOptPeer
}

// Args serializes opts to cli args
func (o SetOpt) Args() []string {
	args := []string{"set", o.Interface}
	if o.ListenPort != 0 {
		args = append(args, "listen-port", strconv.Itoa(o.ListenPort))
	}
	if o.FwMark != "" {
		args = append(args, "fwmark", o.FwMark)
	}
	if o.PrivKeyFpath != "" {
		args = append(args, "private-key", o.PrivKeyFpath)
	}
	for _, p := range o.Peers {
		args = append(args, p.Args()...)
	}
	return args
}

// Set options on an interface
// wg set ...
func Set(opt SetOpt) error {
	return SetCtx(context.Background(), opt)
}

// SetCtx options on an interface
// ctx for process management
// wg set ...
func SetCtx(ctx context.Context, opt SetOpt) error {
	err := exec.CommandContext(ctx, wg, opt.Args()...).Run()
	if err != nil {
		err = fmt.Errorf("set: %v", err)
	}
	return err
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
