package main

import (
	"context"
	"fmt"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
)

// runtimeView exposes the running proxy to the panel.
type runtimeView struct {
	egress    *egress.Manager
	tracker   *proxy.Tracker
	socksAddr string // empty when the SOCKS5 inbound is disabled
}

func (r *runtimeView) Components() []panel.Component {
	state, detail := r.egress.Summary()
	out := []panel.Component{{Name: "egress_manager", State: state, Detail: detail}}
	if r.socksAddr != "" {
		out = append(out, panel.Component{Name: "socks5", State: "running", Detail: "监听 " + r.socksAddr})
	} else {
		out = append(out, panel.Component{Name: "socks5", State: "disabled", Detail: "未配置 capture.socks_listen"})
	}
	snap := r.tracker.Snapshot()
	out = append(out,
		panel.Component{Name: "connections", State: "running", Detail: fmt.Sprintf("活动 %d，累计 %d，失败 %d", len(snap.Active), snap.Total, snap.Failed)},
		panel.Component{Name: "transparent_capture", State: "not_implemented", Detail: "TUN / TPROXY 透明捕获尚未实现（DESIGN §4.1），目前只能通过 SOCKS5 入口使用"},
		panel.Component{Name: "dns", State: "not_implemented", Detail: "FakeIP / 分流 DNS 尚未实现（DESIGN §4.2、§4.8）；出口槽位内的域名通过该出口做 DoH 解析"},
	)
	return out
}

func (r *runtimeView) Egress() any { return r.egress.Status() }

func (r *runtimeView) Tailnet(ctx context.Context) (any, any, error) {
	peers, err := r.egress.Peers(ctx)
	if peers == nil {
		return r.egress.Account(), nil, err
	}
	return r.egress.Account(), peers, err
}

func (r *runtimeView) ApplyEgress(cfg *config.Config) error { return r.egress.Apply(cfg) }

func (r *runtimeView) SetAuthKey(key string) error { return r.egress.SetAuthKey(key) }

func (r *runtimeView) ClearAuthKey() error { return r.egress.ClearAuthKey() }

func (r *runtimeView) SetRelayToken(name, token string) error {
	return r.egress.SetRelayToken(name, token)
}

func (r *runtimeView) Connections() any { return r.tracker.Snapshot() }
