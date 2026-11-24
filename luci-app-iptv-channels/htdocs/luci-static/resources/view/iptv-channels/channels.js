'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require ui';

var callChannels = rpc.declare({
	object: 'iptv-channels',
	method: 'channels'
});

var callDownload = rpc.declare({
	object: 'iptv-channels',
	method: 'download',
	params: ['file', 'offset', 'length']
});

/* 通过 rpcd 分块读取输出文件并保存到本地 (不依赖 /www 可写) */
var DOWNLOAD_FILES = [
	{ name: 'sctv.txt', label: 'sctv.txt（DIYP 直播源）', mime: 'text/plain' },
	{ name: 'sctv.m3u', label: 'sctv.m3u', mime: 'audio/x-mpegurl' },
	{ name: 'epg.xml', label: 'epg.xml（XMLTV EPG）', mime: 'application/xml' }
];
var DOWNLOAD_CHUNK = 65536;

function handleDownload(fname, btn) {
	var chunks = [];
	var offset = 0;
	var received = 0;
	var total = 0;
	var oldText = btn.textContent;
	btn.disabled = true;

	function next() {
		return callDownload(fname, offset, DOWNLOAD_CHUNK).then(function (res) {
			if (!res || !res.success) {
				throw new Error((res && res.msg) || _('读取失败'));
			}
			total = res.size;
			var bin = atob(res.content || '');
			var bytes = new Uint8Array(bin.length);
			for (var i = 0; i < bin.length; i++)
				bytes[i] = bin.charCodeAt(i);
			chunks.push(bytes);
			offset += bin.length;
			received = offset;
			btn.textContent = _('下载中 %d%%…').format(
				total > 0 ? Math.floor(received * 100 / total) : 100);
			if (!res.eof && offset < total)
				return next();
			/* 拼接所有分块并保存 */
			var all = new Uint8Array(received);
			var pos = 0;
			chunks.forEach(function (c) {
				all.set(c, pos);
				pos += c.length;
			});
			var url = URL.createObjectURL(new Blob([all], { type: mimeOf(fname) }));
			var a = document.createElement('a');
			a.href = url;
			a.download = fname;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
		}).catch(function (err) {
			ui.addNotification(null, E('p', {}, _('下载 %s 失败: %s')
				.format(fname, err.message || err)), 'error');
		}).finally(function () {
			btn.textContent = oldText;
			btn.disabled = false;
		});
	}

	return next();
}

function mimeOf(fname) {
	for (var i = 0; i < DOWNLOAD_FILES.length; i++)
		if (DOWNLOAD_FILES[i].name === fname)
			return DOWNLOAD_FILES[i].mime;
	return 'application/octet-stream';
}

function renderTable(channels) {
	var rows = [];
	if (!channels || !channels.length) {
		rows.push(E('tr', {}, E('td', { 'colspan': '3', 'style': 'text-align:center; padding:1em' },
			_('暂无频道数据，请先在设置页点击"保存并立即更新"'))));
	} else {
		channels.forEach(function (ch) {
			rows.push(E('tr', {}, [
				E('td', { 'style': 'white-space:nowrap' }, ch.name || ''),
				E('td', {}, ch.url || ''),
				E('td', {}, ch.catchup || '—'),
			]));
		});
	}
	return E('table', { 'class': 'table cbi-section-table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('频道名称')),
			E('th', { 'class': 'th' }, _('播放地址（组播转 HTTP）')),
			E('th', { 'class': 'th' }, _('回放 / 时移地址')),
		])
	].concat(rows));
}

return view.extend({
	load: function () {
		return callChannels();
	},

	render: function (data) {
		var btns = [];
		DOWNLOAD_FILES.forEach(function (f) {
			btns.push(E('button', {
				'class': 'btn cbi-button',
				'style': 'margin-right:1em',
				'click': function (ev) {
					var btn = ev.currentTarget;
					if (btn && !btn.disabled)
						handleDownload(f.name, btn);
				}
			}, _('下载 %s').format(f.label)));
		});

		var links = E('div', { 'class': 'cbi-section', 'style': 'margin-bottom:1.5em' }, [
			E('h3', {}, _('输出文件下载')),
			E('div', { 'style': 'margin-bottom:.5em' }, btns),
			E('p', { 'style': 'color:var(--text-color-secondary,#888); font-size:12px' },
				_('通过 LuCI 内部接口读取 /etc/iptv-channels/output 下的文件并保存到本机，无需 /www 目录可写，也不受固件权限限制。')),
		]);

		var container = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('频道列表')),
			E('div', { 'id': 'iptv-channels-table' }, renderTable(data.channels)),
		]);

		var node = E('div', {}, [
			E('h2', { 'class': 'cbi-title' }, _('IPTV 频道列表')),
			links,
			container,
		]);

		poll.add(L.bind(function () {
			return callChannels().then(function (res) {
				var el = document.getElementById('iptv-channels-table');
				if (el)
					dom.content(el, renderTable(res.channels));
			});
		}, this), 10);
		poll.start();

		return node;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
