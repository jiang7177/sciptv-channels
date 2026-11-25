'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require dom';
'require ui';

var callRun = rpc.declare({
	object: 'iptv-channels',
	method: 'run'
});

var callStatus = rpc.declare({
	object: 'iptv-channels',
	method: 'status'
});

var callLog = rpc.declare({
	object: 'iptv-channels',
	method: 'log',
	params: ['lines']
});

var callCron = rpc.declare({
	object: 'iptv-channels',
	method: 'cron',
	params: ['action']
});

var callInterfaces = rpc.declare({
	object: 'iptv-channels',
	method: 'interfaces'
});

var callDiscover = rpc.declare({
	object: 'iptv-channels',
	method: 'discover',
	params: ['action', 'timeout']
});

function fmtTime(unix) {
	if (!unix || unix <= 0)
		return '从未生成';
	var d = new Date(unix * 1000);
	function p(n) { return (n < 10 ? '0' : '') + n; }
	return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
		+ ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

return view.extend({
	handleRunUpdate: function (m, ev) {
		return m.save().then(function () {
			return callRun();
		}).then(function (res) {
			if (res && res.success)
				ui.addNotification(null, E('p', {}, _('更新任务已启动，请观察下方日志输出。')), 'info');
			else
				ui.addNotification(null, E('p', {}, (res && res.msg) ? res.msg : _('启动失败')), 'error');
			return Promise.all([this.refreshStatus(), this.refreshLog()]);
		}.bind(this)).catch(L.bind(ui.addNotification, ui, null, E('p'), 'error'));
	},

	handleApplyCron: function (m, ev) {
		return m.save().then(function () {
			return callCron('apply');
		}).then(function () {
			ui.addNotification(null, E('p', {}, _('定时任务已应用')), 'info');
		}).catch(function () {
			ui.addNotification(null, E('p', {}, _('应用定时任务失败，请检查 /etc/crontabs/root 权限')), 'error');
		});
	},

	handleDiscover: function (m, ev) {
		var btn = ev.target;
		return m.save().then(function () {
			return callDiscover({ action: 'start', timeout: 30 });
		}).then(function (res) {
			if (res && res.running) {
				ui.addNotification(null, E('p', {}, _(
					'嗅探已启动，正在监听机顶盒认证流量（默认 30 秒）。'
					+ '请确保机顶盒已开机并接在 IPTV 线路上，嗅探期间重启一次机顶盒或切换频道可触发认证请求。')),
					'info');
				this.pollDiscover(60);
			}
			else
				ui.addNotification(null, E('p', {}, _('嗅探启动失败')), 'error');
		}.bind(this)).catch(L.bind(ui.addNotification, ui, null, E('p'), 'error'));
	},

	pollDiscover: function (retries) {
		if (retries <= 0) {
			ui.addNotification(null, E('p', {}, _('嗅探等待超时，请查看运行日志')), 'warning');
			return Promise.resolve();
		}
		return callDiscover({ action: 'poll', timeout: 0 }).then(function (res) {
			if (res && res.running)
				return new Promise(function (resolve) { setTimeout(resolve, 3000); })
					.then(L.bind(this.pollDiscover, this, retries - 1));

			var r = res && res.result;
			if (r && r.success && r.found) {
				var params = r.params || {};
				var lines = Object.keys(params).map(function (k) {
					return k + ': ' + params[k];
				});
				var changed = (r.changed_fields || []);
				ui.addNotification(null, E('div', {}, [
					E('p', {}, _('发现成功！参数已自动写入配置：')),
					E('pre', { 'style': 'white-space:pre-wrap; word-break:break-all; font-size:12px; max-height:260px; overflow:auto' },
						lines.join('\n')),
					changed.length
						? E('p', {}, _('本次更新的字段：') + changed.join(', '))
						: E('p', {}, _('配置无变化'))
				]), 'info');
			}
			else if (r && r.success === false)
				ui.addNotification(null, E('p', {}, _('嗅探失败: ') + (r.msg || '未知错误') + (res.stderr ? '\n' + res.stderr : '')), 'error');
			else
				ui.addNotification(null, E('p', {}, _(
					'嗅探结束，未捕获到机顶盒认证流量。可能原因：机顶盒单播流量不经过嗅探网口（光猫交换芯片不转发）；'
					+ '嗅探期间机顶盒无开关机/换台操作；路由器未安装 tcpdump。'
					+ 'EDS 入口探测不受此影响（结果见日志），账号参数仍需手动或抓包填写。')), 'warning');

			return Promise.all([this.refreshStatus(), this.refreshLog()]);
		}.bind(this)).catch(L.bind(ui.addNotification, ui, null, E('p'), 'error'));
	},

	refreshStatus: function () {
		var runBtn = document.getElementById('iptv-run-btn');
		return callStatus().then(function (res) {
			var badge = document.getElementById('iptv-status-badge');
			if (badge)
				badge.textContent = res.running ? _('运行中…') : _('空闲');
			if (runBtn)
				runBtn.disabled = !!res.running;
			var modeEl = document.getElementById('iptv-mode-label');
			if (modeEl)
				modeEl.textContent = res.mode === 'auto'
					? _('自动（嗅探）') : _('手动');

			['sctv.txt', 'sctv.m3u', 'epg.xml'].forEach(function (f) {
				var el = document.getElementById('iptv-time-' + f);
				if (el && res.output)
					el.textContent = fmtTime(res.output[f]);
			});
		});
	},

	refreshLog: function () {
		return callLog(300).then(function (res) {
			var el = document.getElementById('iptv-log-view');
			if (el && typeof res.log === 'string') {
				el.textContent = res.log || _('暂无日志');
				el.scrollTop = el.scrollHeight;
			}
		});
	},

	render: function () {
		var m, s, o, sniffIfaceOpt;

		m = new form.Map('iptv-channels',
			_('IPTV 频道获取（四川电信）'),
			_('通过 IPTV 线路自动获取电信组播地址、回放地址及官方 EPG 节目单。移植自 <a href="https://github.com/mytv-android/IPTV-channels" target="_blank">mytv-android/IPTV-channels</a>。配置参数可通过机顶盒抓包或读取机顶盒配置获得。'));

		s = m.section(form.NamedSection, 'main', 'main');
		s.addremove = false;

		/* ---- 自动模式 tab ---- */
		s.tab('auto', _('自动模式'));

		o = s.taboption('auto', form.ListValue, 'mode', _('运行模式'),
			_('自动模式通过 tcpdump 混杂嗅探 IPTV 网口上机顶盒的明文 HTTP 认证报文，自动获取 UserID / 机顶盒 IP / MAC / STBID / STBType / 模板 / 区域 / EDS 入口地址并写回配置；'
			+ '无论 EDS 服务器怎么变，机顶盒发出的报文就是它当前实际使用的平台，重新嗅探即可自动跟随，无需重新抓包。'
			+ '需要路由器安装 tcpdump（opkg install tcpdump）。'));
		o.value('manual', _('手动模式（手动填写认证参数）'));
		o.value('auto', _('自动模式（嗅探机顶盒流量自动获取）'));
		o.default = 'manual';

		sniffIfaceOpt = s.taboption('auto', form.ListValue, 'sniff_interface', _('嗅探网口'),
			_('监听机顶盒流量的网口。留空则自动检测：优先选择路由到 EDS 的网口，其次 10 开头的 IPTV 内网网口（如 eth2.49）。若机顶盒接在路由器 LAN 口下，请选择 br-lan。'
			+ '注意：光猫交换芯片不转发机顶盒单播帧时嗅探会一无所获，此时 EDS 入口探测仍然有效，账号参数只需手动/抓包填写一次'));
		sniffIfaceOpt.value('', _('自动检测'));

		o = s.taboption('auto', form.Value, 'sniff_timeout', _('嗅探时长（秒）'),
			_('机顶盒开机 / 刷新页面时才会产生认证流量，太短可能捕获不到'));
		o.datatype = 'range(5,300)';
		o.default = '30';
		o.placeholder = '30';

		o = s.taboption('auto', form.Flag, 'auto_bruteforce', _('自动爆破 key'),
			_('嗅探到 Authenticator 且配置中无 key 时自动爆破 8 位 key（校验解密结果中的 UserID/STBID）。路由器 CPU 较慢，全空间可能需要数小时，建议保持关闭并手动填写 key'));
		o.default = '0';

		o = s.taboption('auto', form.Flag, 'eds_scan', _('EDS 入口失效时自动扫描网段'),
			_('所有已知入口（当前入口 + 历史节点）都不可达时，并发扫描 ' 
			+ '182.138.0.0/16 网段的 8082/8001 端口寻找新 EDS 入口。耗时数分钟，默认关闭。'
			+ '入口探测会自动跟随：电信 EDS 入口以 302 方式指向当前 EPG 节点，节点轮换时重新探测即可恢复，无需重新抓包。'));
		o.default = '0';

		/* ---- 认证信息 tab ---- */
		s.tab('base', _('认证信息'));

		o = s.taboption('base', form.Value, 'ip', _('机顶盒 IP'));
		o.rmempty = false;
		o.datatype = 'ipaddr';
		o.description = _('机顶盒在 IPTV 内网线路上的 IP 地址（自动模式可嗅探获取）');

		o = s.taboption('base', form.Value, 'user_id', _('UserID'));
		o.rmempty = false;
		o.description = _('机顶盒账号 ID，通常为电话号码');

		o = s.taboption('base', form.Value, 'mac', _('MAC 地址'));
		o.rmempty = false;
		o.datatype = 'macaddr';

		o = s.taboption('base', form.Value, 'stbid', _('STBID'));
		o.rmempty = false;

		o = s.taboption('base', form.Value, 'key', _('8 位加密 Key'));
		o.password = true;
		o.description = _('3DES 加密 key（8 位数字），抓包获取。留空时若填写了 Authenticator 将尝试自动破解');

		o = s.taboption('base', form.Value, 'key_declared', _('认证串声明 Key（可选）'),
			_('写入 Authenticator 首字段的 key。部分平台加密 key 与声明 key 不一致（需从 Authenticator 爆破结果中选择实际加密成功的一个），留空则与加密 key 相同'));

		o = s.taboption('base', form.TextValue, 'authenticator', _('Authenticator'));
		o.rows = 4;
		o.monospace = true;
		o.description = _('机顶盒认证串。仅在 key 为空时用于自动破解 key（需要 python3-pycryptodome）');

		o = s.taboption('base', form.Value, 'authentication_ip', _('EPG 认证服务器'),
			_('从机顶盒抓包获取（如 http://x.x.x.x:8082）。留空且无自动探测入口时无法认证；自动模式发现入口后会自动写入'));
		o.placeholder = 'http://x.x.x.x:8082';

		o = s.taboption('base', form.Value, 'stb_type', _('STBType'));
		o = s.taboption('base', form.Value, 'stb_version', _('STBVersion'));
		o = s.taboption('base', form.Value, 'template_name', _('templateName'));
		o = s.taboption('base', form.Value, 'area_id', _('areaId'));
		o = s.taboption('base', form.Value, 'user_agent', _('User-Agent'));
		o.placeholder = 'Mozilla/5.0 (X11; Android x86_64; ChromiumBrowser) …SkWebKit-SC-CTC';

		/* ---- 高级选项 tab ---- */
		s.tab('adv', _('高级选项'));

		o = s.taboption('adv', form.Value, 'rtp2httpd', _('RTP2HTTPD 服务器地址'),
			_('组播转 HTTP 的服务器，频道地址会指向该服务器。需自行部署 rtp2httpd / udpxy 等组播转单播工具'));
		o.placeholder = 'http://192.168.5.1:8888';

		o = s.taboption('adv', form.Value, 'epg_git_repo', _('EPG Git 仓库（可选）'),
			_('HTTPS 格式仓库地址，填写后每次更新自动推送 epg.xml（路由器需安装 git）'));
		o = s.taboption('adv', form.Value, 'epg_git_token', _('Git 私有令牌'));
		o.password = true;

		/* ---- 免登录文件服务 ---- */
		o = s.taboption('adv', form.Flag, 'server_enabled', _('免登录文件服务'),
			_('开启后播放器无需登录 LuCI，直接用 http://路由器IP:5141/sctv.m3u 或 /sctv.txt '
			+ '订阅频道列表，EPG 填 /epg.xml。仅提供输出目录白名单文件（防路径穿越），'
			+ '修改端口/地址/来源网段后需点下方"应用设置"重启服务生效。'
			+ '注意：OpenWrt 默认防火墙已阻断 WAN 侧入站，不会暴露到公网'));
		o.default = '1';

		o = s.taboption('adv', form.Value, 'server_port', _('文件服务端口'),
			_('免登录文件服务监听端口'));
		o.datatype = 'range(1,65535)';
		o.default = '5141';
		o.placeholder = '5141';
		o.depends('server_enabled', '1');

		o = s.taboption('adv', form.Value, 'server_bind', _('监听地址'),
			_('默认 0.0.0.0 监听所有网口；也可只绑定某网口 IP（如 192.168.123.1）'));
		o.datatype = 'ipaddr("auto")';
		o.placeholder = '0.0.0.0';
		o.depends('server_enabled', '1');

		o = s.taboption('adv', form.Value, 'server_allow_cidr', _('来源网段白名单'),
			_('仅允许指定网段访问文件服务（空格分隔多个，如 192.168.123.0/24 10.0.0.0/8）。'
			+ '留空 = 所有来源可访问（含 WAN 侧，建议填写）'));
		o.placeholder = '192.168.123.0/24';
		o.depends('server_enabled', '1');

		/* ---- 定时任务 tab ---- */
		s.tab('cron', _('定时更新'));

		o = s.taboption('cron', form.Flag, 'cron_enabled', _('启用定时更新'));
		o.default = '0';

		o = s.taboption('cron', form.Value, 'cron_expr', _('Cron 表达式'),
			_('5 字段标准 crontab 表达式，例如 0 5 * * * 表示每天凌晨 5 点更新'));
		o.placeholder = '0 5 * * *';
		o.depends('cron_enabled', '1');

		/* ---- 上游接口（动态网口列表，在 Map 渲染前注册） ---- */
		return callInterfaces().then(function (res) {
			var ifaces = (res && res.interfaces) || [];

			/* 嗅探网口补充动态网口选项 */
			ifaces.forEach(function (i) {
				var label = i.name;
				if (i.ip)
					label += ' (' + i.ip + ')';
				if (i.state && i.state !== 'up')
					label += ' [' + i.state + ']';
				sniffIfaceOpt.value(i.name, label);
			});

			o = s.taboption('adv', form.ListValue, 'upstream_interface', _('上游接口'),
				_('绑定 EPG/认证请求的出口网口，避免请求被路由表引导到错误的出口（电信 EPG 服务器通常仅 IPTV 内网可达）。留空则走系统默认路由。自动模式下会根据 EDS 地址自动检测并跟随。'));
			o.value('', _('跟随系统路由（不绑定）'));
			ifaces.forEach(function (i) {
				var label = i.name;
				if (i.ip)
					label += ' (' + i.ip + ')';
				if (i.state && i.state !== 'up')
					label += ' [' + i.state + ']';
				o.value(i.name, label);
			});

			/* ---- 自定义面板：状态 / 按钮 / 日志 ---- */
			var header = E('div', { 'class': 'cbi-section', 'style': 'margin-bottom:1em' }, [
				E('h3', {}, _('运行状态')),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('任务状态')),
					E('div', { 'class': 'cbi-value-field' },
						E('span', { 'id': 'iptv-status-badge', 'class': 'label' }, _('未知'))),
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('运行模式')),
					E('div', { 'class': 'cbi-value-field' },
						E('span', { 'id': 'iptv-mode-label', 'class': 'label' }, _('未知'))),
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('sctv.txt')),
					E('div', { 'class': 'cbi-value-field' },
						E('span', { 'id': 'iptv-time-sctv.txt' }, '从未生成')),
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('sctv.m3u')),
					E('div', { 'class': 'cbi-value-field' },
						E('span', { 'id': 'iptv-time-sctv.m3u' }, '从未生成')),
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('epg.xml')),
					E('div', { 'class': 'cbi-value-field' },
						E('span', { 'id': 'iptv-time-epg.xml' }, '从未生成')),
				]),
			]);

			var btnDiscover = E('button', {
				'id': 'iptv-discover-btn',
				'class': 'btn cbi-button cbi-button-positive',
				'click': ui.createHandlerFn(this, 'handleDiscover', m),
				'style': 'margin-right:1em'
			}, _('立即发现参数（嗅探）'));

			var btnRun = E('button', {
				'id': 'iptv-run-btn',
				'class': 'btn cbi-button cbi-button-action important',
				'click': ui.createHandlerFn(this, 'handleRunUpdate', m),
				'style': 'margin-right:1em'
			}, _('保存并立即更新'));

			var btnCron = E('button', {
				'class': 'btn cbi-button',
				'click': ui.createHandlerFn(this, 'handleApplyCron', m)
			}, _('应用设置（定时任务/文件服务）'));

			var buttons = E('div', { 'class': 'cbi-page-actions' }, [btnDiscover, btnRun, btnCron]);

			var logPanel = E('div', { 'class': 'cbi-section', 'style': 'margin-top:1.5em' }, [
				E('h3', {}, _('运行日志')),
				E('pre', {
					'id': 'iptv-log-view',
					'style': 'max-height:400px; overflow:auto; white-space:pre-wrap; word-break:break-all; background:var(--background-color-high,#f5f5f5); border:1px solid var(--border-color,#ddd); border-radius:4px; padding:8px; font-size:12px; line-height:1.5'
				}, _('加载中…')),
			]);

			return m.render().then(function (node) {
				var wrap = E('div', {}, [node, header, buttons, logPanel]);

				poll.add(L.bind(function () {
					return Promise.all([this.refreshStatus(), this.refreshLog()]);
				}, this), 5);
				poll.start();
				this.refreshStatus();
				this.refreshLog();

				return wrap;
			}.bind(this));
		}.bind(this));
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
