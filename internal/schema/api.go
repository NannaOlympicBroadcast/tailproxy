package schema

// API returns the OpenAPI 3.1 document of tailproxy's REST API (the panel).
// Request bodies for egress and rules reuse the config schema's items.
func API() map[string]any {
	cfg := Config()["properties"].(map[string]any)
	egressItem := cfg["egress"].(map[string]any)["items"]
	ruleItem := cfg["rules"].(map[string]any)["items"]

	obj := func(desc string) map[string]any { return map[string]any{"type": "object", "description": desc} }
	jsonBody := func(s map[string]any) map[string]any {
		return map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": s}}}
	}
	ok := func(desc string, s map[string]any) map[string]any {
		r := map[string]any{"description": desc}
		if s != nil {
			r["content"] = map[string]any{"application/json": map[string]any{"schema": s}}
		}
		return map[string]any{
			"200": r,
			"401": map[string]any{"description": "缺少或错误的访问令牌"},
		}
	}
	errs := func(r map[string]any, codes map[string]string) map[string]any {
		for c, d := range codes {
			r[c] = map[string]any{"description": d, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
		}
		return r
	}
	op := func(id, summary string, responses map[string]any, extra ...map[string]any) map[string]any {
		o := map[string]any{"operationId": id, "summary": summary, "responses": responses}
		for _, e := range extra {
			for k, v := range e {
				o[k] = v
			}
		}
		return o
	}
	revision := map[string]any{"type": "string", "description": "读取时得到的配置文件修订号（sha256）；与当前不一致时返回 409"}

	paths := map[string]any{
		"/api/v1/status": map[string]any{"get": op("getStatus", "版本、运行时长和各组件状态", ok("状态", obj("components[]: name / state / detail")))},
		"/api/v1/config": map[string]any{"get": op("getConfig", "当前生效的配置（只含环境变量名，不含密钥）", ok("配置", map[string]any{"$ref": "#/components/schemas/Config"}))},
		"/api/v1/config/reload": map[string]any{"post": op("reloadConfig", "重新加载配置文件；失败时保留旧配置",
			errs(ok("已加载", obj("")), map[string]string{"400": "配置校验失败"}))},
		"/api/v1/egress": map[string]any{
			"get": op("getEgress", "已配置的出口、运行状态和修订号", ok("出口", map[string]any{
				"type": "object",
				"properties": map[string]any{
					"configured": map[string]any{"type": []string{"array", "null"}, "items": egressItem},
					"runtime":    map[string]any{"type": "array", "items": obj("name / kind（slot、relay、group、main）/ state / detail / exit_node / relay / health …")},
					"revision":   revision,
				},
			})),
			"put": op("putEgress", "保存 egress 段（只改这一段，旧文件存为 .bak）并立即应用",
				errs(ok("已保存", obj("ok / revision / backup / warning")), map[string]string{"400": "校验失败（如规则仍引用被删除的出口）", "409": "修订号过期", "415": "需要 application/json"}),
				map[string]any{"requestBody": jsonBody(map[string]any{
					"type": "object", "required": []string{"revision", "egress"}, "additionalProperties": false,
					"properties": map[string]any{"revision": revision, "egress": map[string]any{"type": "array", "items": egressItem}},
				})}),
		},
		"/api/v1/egress/{name}/relay-token": map[string]any{"put": op("putRelayToken", "保存中继出口的令牌（写入状态目录，权限 600，不写配置文件）",
			errs(ok("已保存", obj("ok")), map[string]string{"400": "没有这个中继出口，或令牌太短"}),
			map[string]any{
				"parameters": []any{map[string]any{"name": "name", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
				"requestBody": jsonBody(map[string]any{"type": "object", "required": []string{"token"}, "additionalProperties": false,
					"properties": map[string]any{"token": map[string]any{"type": "string", "minLength": 16, "maxLength": 255}}}),
			})},
		"/api/v1/tailnet": map[string]any{"get": op("getTailnet", "主节点登录状态、auth key 状态和账号下的设备", ok("tailnet", obj("account / peers（登录前为 null）/ peers_error")))},
		"/api/v1/tailnet/authkey": map[string]any{
			"put": op("putAuthKey", "保存 auth key（新节点自动登录）", errs(ok("已保存", obj("ok")), map[string]string{"400": "不是 tskey- 开头，或来自环境变量不可修改"}),
				map[string]any{"requestBody": jsonBody(map[string]any{"type": "object", "required": []string{"auth_key"}, "additionalProperties": false,
					"properties": map[string]any{"auth_key": map[string]any{"type": "string", "pattern": "^tskey-"}}})}),
			"delete": op("deleteAuthKey", "删除保存的 auth key", ok("已删除", obj("ok"))),
		},
		"/api/v1/connections": map[string]any{"get": op("getConnections", "活动连接、最近 200 条结束的连接和域名可见度统计（bypass）",
			ok("连接", obj("active[] / recent[] / total / failed / bypass")))},
		"/api/v1/rules": map[string]any{
			"get": op("getRules", "规则、可选目标和修订号", ok("规则", map[string]any{"type": "object", "properties": map[string]any{
				"rules": map[string]any{"type": "array", "items": ruleItem}, "targets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"implicit_final": map[string]any{"type": "boolean"}, "revision": revision}})),
			"put": op("putRules", "保存整套规则（只改 rules 段）并立即生效",
				errs(ok("已保存", obj("ok / rules / revision / backup")), map[string]string{"400": "规则校验失败", "409": "修订号过期", "415": "需要 application/json"}),
				map[string]any{"requestBody": jsonBody(map[string]any{"type": "object", "required": []string{"revision", "rules"}, "additionalProperties": false,
					"properties": map[string]any{"revision": revision, "rules": map[string]any{"type": "array", "items": ruleItem}}})}),
		},
		"/api/v1/rules/test": map[string]any{"post": op("testRules", "测试域名 / IP / 端口命中哪条规则；带 rules 时用未保存的草稿测试",
			errs(ok("命中结果", map[string]any{"type": "object", "properties": map[string]any{
				"rule_index": map[string]any{"type": "integer", "description": "-1 表示未命中（隐式 final: direct）"},
				"target":     map[string]any{"type": "string"}, "implicit": map[string]any{"type": "boolean"}, "reason": map[string]any{"type": "string"}}}),
				map[string]string{"400": "参数或草稿规则无效"}),
			map[string]any{"requestBody": jsonBody(map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
				"domain": map[string]any{"type": "string"}, "ip": map[string]any{"type": "string"},
				"port":  map[string]any{"type": "integer", "minimum": 0, "maximum": 65535},
				"rules": map[string]any{"type": "array", "items": ruleItem}}})})},
		"/metrics": map[string]any{"get": op("getMetrics", "Prometheus 文本格式指标", map[string]any{
			"200": map[string]any{"description": "指标", "content": map[string]any{"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}},
			"401": map[string]any{"description": "缺少或错误的访问令牌"},
		})},
	}
	cfgSchema := Config()
	delete(cfgSchema, "$schema")
	delete(cfgSchema, "$id")
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "tailproxy REST API",
			"version":     "v1",
			"description": "本机面板的 REST API（默认 http://127.0.0.1:7708）。所有请求需要 Authorization: Bearer <令牌>；令牌见 tailproxy token。写操作拒绝跨站请求。",
		},
		"servers":  []any{map[string]any{"url": "http://127.0.0.1:7708"}},
		"security": []any{map[string]any{"bearer": []any{}}},
		"paths":    paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
			"schemas": map[string]any{
				"Config": cfgSchema,
				"Error": map[string]any{"type": "object", "properties": map[string]any{
					"error":  map[string]any{"type": "string"},
					"errors": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				}},
			},
		},
	}
}
