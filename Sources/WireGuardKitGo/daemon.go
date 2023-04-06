package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/smallzstd"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

var programPath string = "mem:"               //TODO: change mem: to a real path that iOS could use
var socketPath string = "/tmp/miragenet.sock" //TODO: find you iOS app bundle ID and use it as the socket path
//    socketPath := "/var/mobile/Containers/Data/Application/ABC12345-6789-0123-4567-89ABCDEF0123/Library/Caches/mysocket.sock"

type serverOptions struct {
	VarRoot    string
	LoginFlags controlclient.LoginFlags
}

// 实际创建daemon IPN
func StartDaemon(ctx context.Context, logf logger.Logf, logid string) error { // lbChn chan *ipnlocal.LocalBackend) {
	ln, err := safesocket.Listen(socketPath)
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	signal.Ignore(syscall.SIGPIPE)
	go func() {
		select {
		case s := <-interrupt:
			logf("miraged got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
			// 继续
		}
	}()

	srv := ipnserver.New(logf, logid)

	var lbErr syncs.AtomicValue[error]

	go func() {
		t0 := time.Now()
		lb, err := getLocalBackend(ctx, logf, logid)
		if err == nil {
			logf("got LocalBackend in %v", time.Since(t0).Round(time.Millisecond))
			srv.SetLocalBackend(lb)
			return
		}
		lbErr.Store(err) // before the following cancel
		cancel()         // make srv.Run below complete
	}()

	err = srv.Run(ctx, ln)

	if err != nil && lbErr.Load() != nil {
		return fmt.Errorf("getLocalBackend error: %v", lbErr.Load())
	}

	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("ipnserver.Run: %w", err)
	}
	return nil
}

func getLocalBackend(ctx context.Context, logf logger.Logf, logid string) (_ *ipnlocal.LocalBackend, retErr error) {
	linkMon, err := monitor.New(logf)
	if err != nil {
		return nil, fmt.Errorf("monitor.New: %w", err)
	}

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	e, onlyNetstack, err := createEngine(logf, linkMon, dialer)
	if err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	if _, ok := e.(wgengine.ResolvingEngine).GetResolver(); !ok {
		panic("internal error: exit node resolver not wired up")
	}

	ns, err := newNetstack(logf, dialer, e)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = onlyNetstack
	ns.ProcessSubnets = true

	if onlyNetstack {
		dialer.UseNetstackForIP = func(ip netip.Addr) bool {
			_, ok := e.PeerForIP(ip)
			return ok
		}
		dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return ns.DialContextTCP(ctx, dst)
		}
	}

	e = wgengine.NewWatchdog(e)

	opts := serverOptions{
		VarRoot: programPath,
	}

	store, err := store.New(logf, filepath.Join(programPath, "server-state.conf"))
	if err != nil {
		return nil, fmt.Errorf("store.New: %w", err)
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logid, store, dialer, e, opts.LoginFlags)

	if err != nil {
		return nil, fmt.Errorf("ipnlocal.NewLocalBackend: %w", err)
	}
	lb.SetVarRoot(opts.VarRoot)
	if root := lb.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"))
	}
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})

	if err := ns.Start(lb); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}
	return lb, nil
}

func createEngine(logf logger.Logf, linkMon *monitor.Mon, dialer *tsdial.Dialer) (e wgengine.Engine, onlyNetstack bool, err error) {
	var errs []error
	for _, name := range strings.Split("TODO", ",") {
		logf("wgengine.NewUserspaceEngine(tun %q) ...", name)
		e, onlyNetstack, err = tryEngine(logf, linkMon, dialer, name)
		if err == nil {
			return e, onlyNetstack, nil
		}
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", name, err)
		errs = append(errs, err)
	}
	return nil, false, multierr.New(errs...)
}

var tstunNew func(logf logger.Logf, tunName string) (tun.Device, string, error)

func tryEngine(logf logger.Logf, linkMon *monitor.Mon, dialer *tsdial.Dialer, name string) (e wgengine.Engine, onlyNetstack bool, err error) {
	conf := wgengine.Config{
		ListenPort:  80, //TODO
		LinkMonitor: linkMon,
		Dialer:      dialer,
	}
	onlyNetstack = false
	netns.SetEnabled(true)

	if !onlyNetstack {
		dev, devName, err := tstunNew(logf, name)

		if err != nil {
			tstun.Diagnose(logf, name, err)
			return nil, false, fmt.Errorf("tstun.New(%q): %w", name, err)
		}
		conf.Tun = dev
		if strings.HasPrefix(name, "tap:") {
			conf.IsTAP = true
			e, err := wgengine.NewUserspaceEngine(logf, conf)
			return e, false, err
		}

		r, err := router.New(logf, dev, linkMon)
		if err != nil {
			dev.Close()
			return nil, false, fmt.Errorf("creating router: %w", err)
		}
		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			dev.Close()
			r.Close()
			return nil, false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
		}
		conf.DNS = d
		conf.Router = r
		conf.Router = netstack.NewSubnetRouterWrapper(conf.Router)
	}
	e, err = wgengine.NewUserspaceEngine(logf, conf) //e.wgdev.Up() is called in this function
	if err != nil {
		return nil, false, err
	}
	return e, false, nil
}

func newNetstack(logf logger.Logf, dialer *tsdial.Dialer, e wgengine.Engine) (*netstack.Impl, error) {
	tunDev, magicConn, dns, ok := e.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		return nil, fmt.Errorf("%T is not a wgengine.InternalsGetter", e)
	}
	return netstack.Create(logf, tunDev, e, magicConn, dialer, dns)
}
