package wg

import (
	"io/ioutil"
	"reflect"
	"testing"
)

var (
	tf = "./go_wg_test.sh"
	se = "%v #%v errored: %v"
	sf = "%v #%v \nexp: >%v< \ngot: >%v<"
)

// Interface -> bytes
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

// Peer -> bytes
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
				AllowedIPs: []string{"1.1.1.1/32", "1.0.0.0/16", "10.0.0.0/8", "::1/128"},
			},
			[]byte(`[Peer]
PublicKey = a_short_public_key
AllowedIPs = 1.1.1.1/32, 1.0.0.0/16, 10.0.0.0/8, ::1/128
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

// Conf -> bytes
func TestConfBytes(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(`[Interface]
`),
		}, {
			Conf{
				Interface{
					ListenPort: 5555,
					FwMark:     "0xca6c",
					PrivateKey: "this_is_a_private_key",
				},
				[]Peer{
					{
						PublicKey:  "pubkey_a",
						AllowedIPs: []string{"0.0.0.0/0", "::1/0"},
						Endpoint:   "1.2.3.4/32",
					},
				},
			},
			[]byte(`[Interface]
ListenPort = 5555
FwMark = 0xca6c
PrivateKey = this_is_a_private_key

[Peer]
PublicKey = pubkey_a
AllowedIPs = 0.0.0.0/0, ::1/0
Endpoint = 1.2.3.4/32

`),
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

// bytes -> Conf
func TestNewConfBytes(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(``),
		}, {
			Conf{
				Interface{
					ListenPort: 5678,
					FwMark:     "a_fwmark",
					PrivateKey: "this_is_a_private_key",
				},
				[]Peer{
					{
						PublicKey:           "pubkey_a",
						PresharedKey:        "preshared_key_a",
						AllowedIPs:          []string{"ip_range/1", "ip_range/2", "ip_range/3"},
						Endpoint:            "address/32",
						PersistentKeepalive: 0,
					}, {
						PublicKey:           "pubkey_b",
						PresharedKey:        "preshared_key_b",
						AllowedIPs:          []string{"ip_range/1", "ip_range/2", "ip_range/3"},
						Endpoint:            "address/32",
						PersistentKeepalive: 30,
					},
				},
			},
			[]byte(`[Interface]
PrivateKey = this_is_a_private_key
ListenPort = 5678
FwMark = a_fwmark
[Peer]
	PublicKey = pubkey_a
	PresharedKey=preshared_key_a
	AllowedIPs = ip_range/1,ip_range/2 , ip_range/3
	Endpoint = address/32
[Peer]
PublicKey = pubkey_b

PresharedKey= preshared_key_b
AllowedIPs = ip_range/1
AllowedIPs = ip_range/2, ip_range/3
Endpoint   = address/32
PersistentKeepalive = 30
`),
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

// bytes (status) -> Conf
func TestNewConfStatus(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{},
			[]byte(``),
		}, {
			Conf{
				Interface{
					ListenPort: 52274,
					PublicKey:  "this_is_a_public_key",
					PrivateKey: "(hidden)",
					FwMark:     "0xca6c",
				},
				[]Peer{
					{
						PublicKey:       "another_public_key",
						Endpoint:        "1.2.3.4:51820",
						AllowedIPs:      []string{"0.0.0.0/0"},
						LatestHandshake: 5,
						Received:        13631488,
						Sent:            13680,
					},
				},
			},
			[]byte(`
interface: wg0
  public key: this_is_a_public_key
  private key: (hidden)
  listening port: 52274
  fwmark: 0xca6c

peer: another_public_key
  endpoint: 1.2.3.4:51820
  allowed ips: 0.0.0.0/0
  latest handshake: 5 seconds ago
  transfer: 13.00 MiB received, 13.36 KiB sent
`),
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

// bytes -> Conf
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
			continue
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

// bytes -> []string
func TestShowInterfaces(t *testing.T) {
	cases := []struct {
		I []string
		B []byte
	}{
		{
			[]string{"wg0", "wg1", "wgWhat"},
			[]byte(`#!/bin/env sh
cat << EOF
wg0 wg1 wgWhat
EOF
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "ShowInterfaces setup", i, err)
			continue
		}
		Wg = tf

		ifaces, err := ShowInterfaces()
		if err != nil {
			t.Errorf(se, "ShowInterfaces", i, err)
			continue
		}
		if !reflect.DeepEqual(ifaces, c.I) {
			t.Errorf(sf, "ShowInterfaces", i, c.I, ifaces)
		}
	}
}

// bytes -> Conf
func TestShowConf(t *testing.T) {
	cases := []struct {
		C Conf
		B []byte
	}{
		{
			Conf{
				Interface{
					ListenPort: 52274,
					FwMark:     "0xca6c",
					PrivateKey: "this_is_a_private_key",
				},
				[]Peer{
					{
						PublicKey:  "this_is_a_public_key",
						AllowedIPs: []string{"0.0.0.0/0"},
						Endpoint:   "ip_address:port",
					},
				},
			},
			[]byte(`#!/bin/env sh
cat << EOF
[Interface]
ListenPort = 52274
FwMark = 0xca6c
PrivateKey = this_is_a_private_key

[Peer]
PublicKey = this_is_a_public_key
AllowedIPs = 0.0.0.0/0
Endpoint = ip_address:port
EOF
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "ShowConf setup", i, err)
			continue
		}
		Wg = tf

		conf, err := ShowConf("iface")
		if err != nil {
			t.Errorf(se, "ShowConf", i, err)
			continue
		}
		if !reflect.DeepEqual(conf, c.C) {
			t.Errorf(sf, "ShowConf", i, c.C, conf)
		}
	}
}

// OptPeer -> []string
func TestOptPeerArgs(t *testing.T) {
	pka := 10
	cases := []struct {
		O OptPeer
		A []string
	}{
		{
			OptPeer{
				PublicKey: "this_is_a_public_key",
			},
			[]string{"peer", "this_is_a_public_key"},
		}, {
			OptPeer{
				PublicKey: "pubkey_a",
				Remove:    true,
			},
			[]string{"peer", "pubkey_a", "remove"},
		}, {
			OptPeer{
				PublicKey:           "pubkey_b",
				Endpoint:            "1.2.3.4:5678",
				PersistentKeepalive: &pka,
				AllowedIPs:          []string{"1.1.2.2/16", "10.0.0.0/8"},
			},
			[]string{"peer", "pubkey_b", "endpoint", "1.2.3.4:5678", "persistent-keepalive", "10", "allowed-ips", "1.1.2.2/16,10.0.0.0/8"},
		},
	}
	for i, c := range cases {
		args := c.O.Args()
		if !reflect.DeepEqual(args, c.A) {
			t.Errorf(sf, "OptPeer", i, c.A, args)
		}
	}
}

// opt -> []string
func TestOptArgs(t *testing.T) {
	cases := []struct {
		O Opt
		A []string
	}{
		{
			Opt{
				Interface: "wg0",
			},
			[]string{"set", "wg0"},
		}, {
			Opt{
				Interface:    "wg1",
				ListenPort:   5678,
				FwMark:       "0xca6c",
				PrivKeyFpath: "/etc/super/secret",
				Peers: []OptPeer{
					{
						PublicKey: "pubkey_a",
						Remove:    true,
					},
					{
						PublicKey: "pubkey_b",
						Endpoint:  "8.9.10.11:4321",
					},
				},
			},
			[]string{"set", "wg1", "listen-port", "5678", "fwmark", "0xca6c", "private-key", "/etc/super/secret", "peer", "pubkey_a", "remove", "peer", "pubkey_b", "endpoint", "8.9.10.11:4321"},
		},
	}
	for i, c := range cases {
		args := c.O.Args()
		if !reflect.DeepEqual(args, c.A) {
			t.Errorf(sf, "Opt", i, c.A, args)
		}
	}
}

// not much more than Opt.Args()
func TestSet(t *testing.T) {
	cases := []struct {
		O Opt
		B []byte
	}{
		{
			Opt{
				Interface: "wg0",
			},
			[]byte(`#!/bin/env sh
ans=( "set" "wg0" )
i=0
for arg in $@; do
    if [ "$arg" != ${ans[$i]}  ]; then
        exit 1
    fi
    i=$i+1
done
`),
		}, {
			Opt{
				Interface:    "wg1",
				ListenPort:   5678,
				FwMark:       "0xca6c",
				PrivKeyFpath: "/etc/super/secret",
				Peers: []OptPeer{
					{
						PublicKey: "pubkey_a",
						Remove:    true,
					},
					{
						PublicKey: "pubkey_b",
						Endpoint:  "8.9.10.11:4321",
					},
				},
			},
			[]byte(`#!/bin/env sh
ans=( "set", "wg1", "listen-port", "5678", "fwmark", "0xca6c", "private-key", "/etc/super/secret", "peer", "pubkey_a", "remove", "peer", "pubkey_b", "endpoint", "8.9.10.11:4321" )
i=0
for arg in $@; do
    if [ "$arg" != ${ans[$i]}  ]; then
        exit $i
    fi
    i=$i+1
done
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "Set setup", i, err)
			continue
		}
		Wg = tf

		err = Set(c.O)
		if err != nil {
			t.Errorf(se, "Set", i, err)
			continue
		}
	}
}

func TestSetConf(t *testing.T) {
	cases := []struct {
		F string
		B []byte
	}{
		{
			"/etc/wireguard/iface.conf",
			[]byte(`#!/bin/env sh
ans=( "setconf" "iface" "/etc/wireguard/iface.conf" )
i=0
for arg in $@; do
    if [ "$arg" != ${ans[$i]}  ]; then
        exit 1
    fi
    i=$i+1
done

`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "SetConf setup", i, err)
			continue
		}
		Wg = tf

		err = SetConf("iface", c.F)
		if err != nil {
			t.Errorf(se, "SetConf", i, err)
			continue
		}
	}
}

// TODO add test cases
func TestAddConf(t *testing.T) {
	cases := []struct {
		F string
		B []byte
	}{
		{
			"/etc/wireguard/iface.conf",
			[]byte(`#!/bin/env sh
ans=( "addconf" "iface" "/etc/wireguard/iface.conf" )
i=0
for arg in $@; do
    if [ "$arg" != ${ans[$i]}  ]; then
        exit 1
    fi
    i=$i+1
done

`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "AddConf setup", i, err)
			continue
		}
		Wg = tf

		err = AddConf("iface", c.F)
		if err != nil {
			t.Errorf(se, "AddConf", i, err)
			continue
		}
	}
}

// TODO add test cases
func TestGenKey(t *testing.T) {
	cases := []struct {
		K string
		B []byte
	}{
		{
			"generated_private_key",
			[]byte(`#!/bin/env sh
echo -n generated_private_key
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "GenKey setup", i, err)
			continue
		}
		Wg = tf

		key, err := GenKey()
		if err != nil {
			t.Errorf(se, "GenKey", i, err)
			continue
		}
		if key != c.K {
			t.Errorf(sf, "GenKey", i, c.K, key)
		}
	}
}

func TestGenPsk(t *testing.T) {
	cases := []struct {
		K string
		B []byte
	}{
		{
			"generated_preshared_key",
			[]byte(`#!/bin/env sh
echo -n generated_preshared_key
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "GenPsk setup", i, err)
			continue
		}
		Wg = tf

		key, err := GenPsk()
		if err != nil {
			t.Errorf(se, "GenPsk", i, err)
			continue
		}
		if key != c.K {
			t.Errorf(sf, "GenPsk", i, c.K, key)
		}
	}
}

// TODO add test cases
func TestPubKey(t *testing.T) {
	cases := []struct {
		PubKey, PrivKey string
		B               []byte
	}{
		{
			"expected_public_key",
			"inputted_private_key",
			[]byte(`#!/bin/env sh
read key
if [ "$key" = "inputted_private_key" ]; then
	echo -n expected_public_key
	exit 0
fi
exit 1
`),
		},
	}
	for i, c := range cases {
		err := ioutil.WriteFile(tf, c.B, 0755)
		if err != nil {
			t.Errorf(sf, "PubKey setup", i, err)
			continue
		}
		Wg = tf

		pubkey, err := PubKey(c.PrivKey)
		if err != nil {
			t.Errorf(se, "PubKey", i, err)
			continue
		}
		if pubkey != c.PubKey {
			t.Errorf(sf, "PubKey", i, c.PubKey, pubkey)
		}
	}
}

// The only thing gained by separately testing these is
// testing exec.CommandContext handling of ctx
// func TestShowCtx(t *testing.T) {}
// func TestShowInterfacesCtx(t *testing.T) {}
// func TestShowConfCtx(t *testing.T)       {}
// func TestSetCtx(t *testing.T)            {}
// func TestSetConfCtx(t *testing.T)        {}
// func TestAddConfCtx(t *testing.T)        {}
// func TestGenKeyCtx(t *testing.T)         {}
// func TestGenPskCtx(t *testing.T)         {}
// func TestPubKeyCtx(t *testing.T)         {}
