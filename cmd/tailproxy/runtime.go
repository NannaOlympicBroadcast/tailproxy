package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
)

// runtimeView exposes the running proxy to the panel.
type runtimeView struct {
	engine    kernel.Engine
	egress    *egress.Manager
	tracker   *proxy.Tracker
	socksAddr string // empty when the SOCKS5 inbound is disabled
	capture   *captureRuntime
}

func (r *runtimeView) Components() []panel.Component {
	var out []panel.Component
	if r.engine != nil {
		out = append(out, r.engine.Components()...)
	} else if r.egress != nil {
		state, detail := r.egress.Summary()
		out = append(out, panel.Component{Name: "egress_manager", State: state, Detail: detail})
	}
	if r.socksAddr != "" {
		out = append(out, panel.Component{Name: "socks5", State: "running", Detail: "监听 " + r.socksAddr})
	} else if r.engine == nil || r.engine.Type() == kernel.ModeDavin {
		out = append(out, panel.Component{Name: "socks5", State: "disabled", Detail: "未配置 capture.socks_listen"})
	}
	if r.tracker != nil {
		snap := r.tracker.Snapshot()
		out = append(out,
			panel.Component{Name: "connections", State: "running", Detail: fmt.Sprintf("活动 %d，累计 %d，失败 %d", len(snap.Active), snap.Total, snap.Failed)},
		)
	}
	if r.capture != nil {
		cs, cd, ds, dd := r.capture.Summary()
		out = append(out, panel.Component{Name: "transparent_capture", State: cs, Detail: cd}, panel.Component{Name: "dns", State: ds, Detail: dd})
	} else if r.engine == nil || r.engine.Type() == kernel.ModeDavin {
		out = append(out,
			panel.Component{Name: "transparent_capture", State: "disabled", Detail: "未开启（capture.mode: tproxy 为 Linux nftables 透明捕获；capture.mode: tun 为 TUN 设备，需 root / 管理员）"},
			panel.Component{Name: "dns", State: "disabled", Detail: "随透明捕获开启；出口内的域名通过该出口做 DoH 解析"},
		)
	}
	return out
}

func (r *runtimeView) KernelStatus() any {
	if r.engine != nil {
		return r.engine.Status()
	}
	return nil
}

func (r *runtimeView) Egress() any {
	if r.egress != nil {
		return r.egress.Status()
	}
	return map[string]any{
		"kernel": "bacarra",
		"detail": "Bacarra 模式由系统官方 Tailscale 客户端接管出网，无需嵌入式出口槽位",
	}
}

func (r *runtimeView) Tailnet(ctx context.Context) (any, any, error) {
	if r.egress != nil {
		peers, err := r.egress.Peers(ctx)
		if peers == nil {
			return r.egress.Account(), nil, err
		}
		return r.egress.Account(), peers, err
	}
	return map[string]any{"mode": "bacarra", "notice": "请使用系统官方 Tailscale 客户端管理设备"}, nil, nil
}

func (r *runtimeView) ApplyEgress(cfg *config.Config) error {
	if r.egress != nil {
		return r.egress.Apply(cfg)
	}
	return nil
}

func (r *runtimeView) SetAuthKey(key string) error {
	if r.egress != nil {
		return r.egress.SetAuthKey(key)
	}
	return errors.New("Bacarra 模式由本机官方 Tailscale 客户端管理账号与设备")
}

func (r *runtimeView) ClearAuthKey() error {
	if r.egress != nil {
		return r.egress.ClearAuthKey()
	}
	return nil
}

func (r *runtimeView) SetRelayToken(name, token string) error {
	if r.egress != nil {
		return r.egress.SetRelayToken(name, token)
	}
	return nil
}

func (r *runtimeView) Connections() any {
	if r.tracker != nil {
		return r.tracker.Snapshot()
	}
	return map[string]any{"active": []any{}, "total": 0, "failed": 0}
}
