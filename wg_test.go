package wg

import (
	"io/ioutil"
	"reflect"
	"testing"
)

var (
	tf = "./go_wg_test.sh"
	se = "%v #%v errored: %v"
	sf = "%v #%v \nexp: %v \ngot: %v"
)

func TestInterfaceBytes(t *testing.T) {
	cases := []struct {
		I Interface
		B []byte
	}{
		{
			Interface{},
			[]byte(`[Interface]

`),
		}, {
			Interface{
				ListenPort: 7788,
				PrivateKey: "privateKeysAreBase64==",
			},
			[]byte(`[Interface]
ListenPort = 7788
PrivateKey = privateKeysAreBase64==

`),
		}, {
			Interface{
				5678,
				"afwmark",
				"thisIsALongPrivateKey",
				"pubkey",
			},
			[]byte(`[Interface]
ListenPort = 5678
FwMark = afwmark
PrivateKey = thisIsALongPrivateKey

`),
		},
	}
	for i, c := range cases {
		res := c.I.Bytes()
		long, short := c.B, res
		if len(short) > len(long) {
			long, short = short, long
		}
		for idx, b := range short {
			if long[idx] != b {
				t.Errorf("Interfaxe.Bytes #%v, bytes differ at pos %v expected %v got %v", i, idx, string([]byte{long[idx]}), string([]byte{short[idx]}))
				break
			}
		}
	}
}

func TestPeerBytes(t *testing.T) {
	cases := []struct {
		P Peer
		B []byte
	}{
		{
			Peer{},
			[]byte(`[Peer]

`),
		}, {
			Peer{
				PublicKey:  "a_short_public_key",
				Endpoint:   "127.0.0.1/32",
				AllowedIPs: []string{"1.1.1.1/32", "1.0.0/16", "10.0.0.0/8", "::1/128"},
			},
			[]byte(`[Peer]
PublicKey = a_short_public_key
AllowedIPs = 1.1.1.1/32,1.0.0/16,10.0.0.0/8,::1/128
Endpoint = 127.0.0.1/32

`),
		}, {
			Peer{
				"public_key_goes_here",
				"preshared_key",
				[]string{"0.0.0.0/0"},
				"192.168.0.2/32",
				30, 0, 0, 0,
			},
			[]byte(`[Peer]
PublicKey = public_key_goes_here
PresharedKey = preshared_key
AllowedIPs = 0.0.0.0/0
Endpoint = 192.168.0.2/32
PersistentKeepalive = 30

`),
		},
	}
	for i, c := range cases {
		res := c.P.Bytes()
		if !reflect.DeepEqual(res, c.B) {
			long, short := c.B, res
			if len(short) > len(long) {
				long, short = short, long
			}
			for idx, b := range short {
				if long[idx] != b {
					t.Errorf("Peer.Bytes #%v, bytes differ at pos %v expected %v got %v", i, idx, string([]byte{long[idx]}), string([]byte{short[idx]}))
					break
				}
			}
		}
	}
}

func TestNewConfBytes(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(``),
		},
	}
	for i, c := range cases {
		conf, err := NewConfBytes(c.B)
		if err != nil {
			t.Errorf(se, "NewConfBytes", i, err)
			continue
		}
		if !reflect.DeepEqual(conf, c.C) {
			t.Errorf(sf, "NewConfBytes", i, c.C, conf)
		}
	}
}
func TestNewConfStatus(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(``),
		},
	}
	for i, c := range cases {
		conf, err := NewConfStatus(c.B)
		if err != nil {
			t.Errorf(se, "NewConfStatus", i, err)
			continue
		}
		if !reflect.DeepEqual(conf, c.C) {
			t.Errorf(sf, "NewConfStatus", i, c.C, conf)
		}
	}

}

func TestConfBytes(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(``),
		},
	}
	for i, c := range cases {
		res := c.C.Bytes()
		if !reflect.DeepEqual(res, c.B) {
			long, short := c.B, res
			if len(short) > len(long) {
				long, short = short, long
			}
			for idx, b := range short {
				if long[idx] != b {
					t.Errorf("Conf.Bytes #%v, bytes differ at pos %v expected %v got %v", i, idx, string([]byte{long[idx]}), string([]byte{short[idx]}))
					break
				}
			}

		}
	}
}

func TestShow(t *testing.T) {
	cases := []struct {
		B []byte
		C Conf
	}{
		{
			[]byte(`#!/usr/bin/env sh
cat << EOF
interface: $1
  public key: this_is_a_public_key
  private key: this_is_a_private_key
  listening port: 52274
  fwmark: 0xca6f

peer: peer_public_key_goes_here
  endpoint: 10.56.88.33:51820
  allowed ips: 0.0.0.0/0
  latest handshake: 2 seconds ago
  transfer: 22.40 KiB received, 21.41 KiB sent

peer: peer_public_key_goes_here
  endpoint: 10.56.88.33:51820
  allowed ips: 192.168.0.1/32, 192.168.1.0/24
  latest handshake: 1 year, 56 days, 3 hours, 1 min ago
  transfer: 22.40 GiB received, 21.41 MiB sent
EOF
`),
			Conf{
				Interface{
					PublicKey:  "this_is_a_public_key",
					PrivateKey: "this_is_a_private_key",
					ListenPort: 52274,
					FwMark:     "0xca6f",
				},
				[]Peer{
					{
						PublicKey:       "peer_public_key_goes_here",
						Endpoint:        "10.56.88.33:51820",
						AllowedIPs:      []string{"0.0.0.0/0"},
						LatestHandshake: 2,
						Received:        22937,
						Sent:            21923,
					}, {
						PublicKey:       "peer_public_key_goes_here",
						Endpoint:        "10.56.88.33:51820",
						AllowedIPs:      []string{"192.168.0.1/32", "192.168.1.0/24"},
						LatestHandshake: 36385200,
						Received:        24051816857,
						Sent:            22450012,
					},
				},
			},
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "Show setup", i, err)
		}
		Wg = tf

		conf, err := Show("wgTest")
		if err != nil {
			t.Errorf(se, "Show", i, err)
			continue
		}
		if !reflect.DeepEqual(conf, c.C) {
			t.Errorf(sf, "Show", i, c.C, conf)
		}
	}
}

func TestShowCtx(t *testing.T)           {}
func TestShowInterfaces(t *testing.T)    {}
func TestShowInterfacesCtx(t *testing.T) {}
func TestShowConf(t *testing.T)          {}
func TestShowConfCtx(t *testing.T)       {}
func TestSetOptPeerArgs(t *testing.T)    {}
func TestSetOptArgs(t *testing.T)        {}
func TestSet(t *testing.T)               {}
func TestSetCtx(t *testing.T)            {}
func TestSetConf(t *testing.T)           {}
func TestSetConfCtx(t *testing.T)        {}
func TestAddConf(t *testing.T)           {}
func TestAddConfCtx(t *testing.T)        {}
func TestGenKey(t *testing.T)            {}
func TestGenKeyCtx(t *testing.T)         {}
func TestGenPsk(t *testing.T)            {}
func TestGenPskCtx(t *testing.T)         {}
func TestPubKey(t *testing.T)            {}
func TestPubKeyCtx(t *testing.T)         {}
