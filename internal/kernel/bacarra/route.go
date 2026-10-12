package bacarra

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"tailscale.com/net/tsaddr"
)

// NextHopForPrefix returns the designated NextHop IP for host route injection.
// On Windows, subnet routes require an explicit NextHop (100.100.100.100)
// rather than 0.0.0.0, preventing Windows from marking them as on-link which
// causes WSA error 10049 on the broadcast IP.
func NextHopForPrefix(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return tsaddr.TailscaleServiceIP()
	}
	return tsaddr.TailscaleServiceIPv6()
}

// RouteDriver abstracts platform-specific routing table manipulation.
type RouteDriver interface {
	AddRoute(p netip.Prefix) error
	DeleteRoute(p netip.Prefix) error
}

// RouteManager manages selective host route hijacking into the official Tailscale adapter.
type RouteManager struct {
	mu       sync.Mutex
	adapter  *AdapterInfo
	stateDir string
	logf     func(string, ...any)
	applied  map[netip.Prefix]bool
	driver   RouteDriver
}

// NewRouteManager initializes a new RouteManager for the given adapter and state directory.
func NewRouteManager(adapter *AdapterInfo, stateDir string, logf func(string, ...any)) (*RouteManager, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter cannot be nil")
	}
	driver, err := newPlatformDriver(adapter)
	if err != nil {
		return nil, fmt.Errorf("bacarra: initialize platform route driver: %w", err)
	}
	return NewRouteManagerWithDriver(adapter, stateDir, logf, driver)
}

// NewRouteManagerWithDriver allows constructing a RouteManager with a custom driver (for testing).
func NewRouteManagerWithDriver(adapter *AdapterInfo, stateDir string, logf func(string, ...any), driver RouteDriver) (*RouteManager, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter cannot be nil")
	}
	if driver == nil {
		return nil, errors.New("bacarra: route driver cannot be nil")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &RouteManager{
		adapter:  adapter,
		stateDir: stateDir,
		logf:     logf,
		applied:  make(map[netip.Prefix]bool),
		driver:   driver,
	}, nil
}

// AppliedRoutes returns a copy of the currently applied route prefixes.
func (r *RouteManager) AppliedRoutes() []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	routes := make([]netip.Prefix, 0, len(r.applied))
	for p := range r.applied {
		routes = append(routes, p)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].String() < routes[j].String()
	})
	return routes
}

// Apply calculates the difference between desired and currently applied routes,
// adds new routes, removes deleted routes, and updates the state file atomically.
func (r *RouteManager) Apply(prefixes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	want := make(map[netip.Prefix]bool, len(prefixes))
	for _, p := range prefixes {
		if p.IsValid() {
			want[p.Masked()] = true
		}
	}

	var errs []error

	// 1. Add new routes
	for p := range want {
		if r.applied[p] {
			continue
		}
		if err := r.driver.AddRoute(p); err != nil {
			r.logf("bacarra: error adding route %s: %v", p, err)
			errs = append(errs, fmt.Errorf("add route %s: %w", p, err))
			continue
		}
		r.applied[p] = true
		r.logf("bacarra: added route %s -> %s", p, r.adapter.Name)
	}

	// 2. Remove routes that are no longer wanted
	for p := range r.applied {
		if !want[p] {
			if err := r.driver.DeleteRoute(p); err != nil {
				r.logf("bacarra: error deleting route %s: %v", p, err)
				errs = append(errs, fmt.Errorf("delete route %s: %w", p, err))
			}
			delete(r.applied, p)
			r.logf("bacarra: deleted route %s", p)
		}
	}

	// 3. Atomically persist applied route state
	if r.stateDir != "" {
		routeStrings := make([]string, 0, len(r.applied))
		for p := range r.applied {
			routeStrings = append(routeStrings, p.String())
		}
		sort.Strings(routeStrings)

		state := &RouteState{
			Kernel:       "bacarra",
			AdapterName:  r.adapter.Name,
			AdapterIndex: r.adapter.Index,
			UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
			Routes:       routeStrings,
		}
		if err := SaveRouteState(r.stateDir, state); err != nil {
			errs = append(errs, fmt.Errorf("save route state: %w", err))
		}
	}

	return errors.Join(errs...)
}

// Close safely removes all applied routes and purges the state file.
func (r *RouteManager) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for p := range r.applied {
		if err := r.driver.DeleteRoute(p); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", p, err))
		}
		delete(r.applied, p)
	}

	if r.stateDir != "" {
		if err := RemoveRouteState(r.stateDir); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// TeardownStale reads <stateDir>/bacarra_routes.json and removes any orphaned routes.
func (r *RouteManager) TeardownStale(stateDir string) error {
	return TeardownStale(stateDir, r.logf)
}

// TeardownStale reads the state file from stateDir and removes any orphaned routes left
// by an abnormal process termination or crash. It cleans up the state file upon completion.
func TeardownStale(stateDir string, logf ...func(string, ...any)) error {
	if stateDir == "" {
		return nil
	}
	var logger func(string, ...any)
	if len(logf) > 0 && logf[0] != nil {
		logger = logf[0]
	} else {
		logger = func(string, ...any) {}
	}

	state, err := ReadRouteState(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		logger("bacarra: corrupt or invalid route state file in %s, removing: %v", stateDir, err)
		_ = RemoveRouteState(stateDir)
		return fmt.Errorf("read stale route state: %w", err)
	}

	logger("bacarra: found stale route state with %d routes on adapter %q (index %d)", len(state.Routes), state.AdapterName, state.AdapterIndex)

	var errs []error
	driver, err := platformDriverForState(state)
	if err == nil && driver != nil {
		for _, rStr := range state.Routes {
			p, err := netip.ParsePrefix(rStr)
			if err != nil {
				continue
			}
			if err := driver.DeleteRoute(p); err != nil {
				logger("bacarra: error deleting stale route %s: %v", p, err)
				errs = append(errs, fmt.Errorf("delete stale route %s: %w", p, err))
			} else {
				logger("bacarra: deleted stale route %s", p)
			}
		}
	} else {
		logger("bacarra: warning: could not initialize platform driver for stale routes: %v", err)
	}

	if err := RemoveRouteState(stateDir); err != nil {
		errs = append(errs, err)
	} else {
		logger("bacarra: removed stale route state file in %s", stateDir)
	}

	return errors.Join(errs...)
}
