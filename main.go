package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, `Usage: %s <wireguard.conf> <listen-addr>`, os.Args[0])
		os.Exit(1)
	}

	wgConfFile := os.Args[1]
	socksListen := os.Args[2]

	mtu, localAddr, dnsAddrs, ipcSet, err := parseWireGuardConf(wgConfFile)
	if err != nil {
		log.Fatalf("parse wireguard config: %v", err)
	}

	tunDev, netStack, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, dnsAddrs, mtu)
	if err != nil {
		log.Fatalf("create netstack tun: %v", err)
	}

	wgDevice := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, "wg"))
	defer wgDevice.Close()

	if err := wgDevice.IpcSet(ipcSet); err != nil {
		log.Fatalf("ipc set: %v", err)
	}

	if err := wgDevice.Up(); err != nil {
		log.Fatalf("wireguard up: %v", err)
	}

	listener, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Fatalf("listen on %s: %v", socksListen, err)
	}
	defer listener.Close()

	srv := &Server{
		Logf: log.Printf,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return netStack.DialContext(ctx, network, address)
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf("SOCKS5 listening on %s", listener.Addr())
	if err := srv.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("socks5 serve: %v", err)
	}
}

func base64ToHex(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	return hex.EncodeToString(decoded), nil
}

func parseWireGuardConf(path string) (int, netip.Addr, []netip.Addr, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, netip.Addr{}, nil, "", err
	}

	var (
		mtu         = 1420 // default WireGuard MTU
		localAddr   netip.Addr
		dnsAddrs    []netip.Addr
		ipcBuilder  strings.Builder
		inInterface bool
		inPeer      bool
	)

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			inInterface = strings.EqualFold(line, "[Interface]")
			inPeer = strings.EqualFold(line, "[Peer]")
			if inPeer {
				ipcBuilder.WriteString("public_key=")
			}
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if inInterface {
			switch strings.ToLower(key) {
			case "privatekey":
				hexKey, err := base64ToHex(value)
				if err != nil {
					return 0, netip.Addr{}, nil, "", fmt.Errorf("convert private key: %v", err)
				}
				ipcBuilder.WriteString("private_key=" + hexKey + "\n")
			case "address":
				addr := value
				if idx := strings.Index(addr, "/"); idx != -1 {
					addr = addr[:idx]
				}
				localAddr, err = netip.ParseAddr(addr)
				if err != nil {
					return 0, netip.Addr{}, nil, "", fmt.Errorf("parse address: %v", err)
				}
			case "dns":
				for _, dns := range strings.Split(value, ",") {
					dns = strings.TrimSpace(dns)
					d, err := netip.ParseAddr(dns)
					if err != nil {
						return 0, netip.Addr{}, nil, "", fmt.Errorf("parse dns: %v", err)
					}
					dnsAddrs = append(dnsAddrs, d)
				}
			case "mtu":
				mtu, err = strconv.Atoi(value)
				if err != nil {
					return 0, netip.Addr{}, nil, "", fmt.Errorf("parse mtu: %v", err)
				}
			case "listenport":
				ipcBuilder.WriteString("listen_port=" + value + "\n")
			}
		} else if inPeer {
			switch strings.ToLower(key) {
			case "publickey":
				hexKey, err := base64ToHex(value)
				if err != nil {
					return 0, netip.Addr{}, nil, "", fmt.Errorf("convert public key: %v", err)
				}
				ipcBuilder.WriteString(hexKey + "\n")
			case "presharedkey":
				hexKey, err := base64ToHex(value)
				if err != nil {
					return 0, netip.Addr{}, nil, "", fmt.Errorf("convert preshared key: %v", err)
				}
				ipcBuilder.WriteString("preshared_key=" + hexKey + "\n")
			case "endpoint":
				ipcBuilder.WriteString("endpoint=" + value + "\n")
			case "persistentkeepalive":
				ipcBuilder.WriteString("persistent_keepalive_interval=" + value + "\n")
			case "allowedips":
				for _, ip := range strings.Split(value, ",") {
					ip = strings.TrimSpace(ip)
					ipcBuilder.WriteString("allowed_ip=" + ip + "\n")
				}
			}
		}
	}

	if !localAddr.IsValid() {
		return 0, netip.Addr{}, nil, "", errors.New("no Address found in [Interface]")
	}

	return mtu, localAddr, dnsAddrs, ipcBuilder.String(), nil
}
