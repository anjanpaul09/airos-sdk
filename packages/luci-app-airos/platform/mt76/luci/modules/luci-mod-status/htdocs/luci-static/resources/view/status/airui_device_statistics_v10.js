'use strict';
'require view';
'require poll';
'require rpc';

var callStatusStatistics = rpc.declare({ object: 'airui.status', method: 'snapshot', expect: { '': {} } });

var pollInterval = 10;
var maxPoints = 24;
var statisticsGeneration = 0;

function updatedLabel() {
	return _('Updated at %s').format(new Date().toLocaleTimeString());
}

function envelopeData(response) {
	return response && response.ok !== false && response.data ? response.data : {};
}

function cleanId(name) {
	return String(name || 'iface').replace(/[^A-Za-z0-9_-]/g, '_');
}

function fmtBytes(v) {
	return '%1024.1mB'.format(Math.max(0, v || 0));
}

function fmtRate(v) {
	v = Math.max(0, v || 0);

	if (v < 1024)
		return '%d B/s'.format(Math.round(v));

	return '%1024.1mB/s'.format(v);
}

function fmtLoad(v) {
	return '%.2f'.format(v || 0);
}

function parseProcNetDev(text) {
	var rows = {};
	var lines = (text || '').split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var m = lines[i].match(/^\s*([^:]+):\s*(.*)$/);

		if (!m)
			continue;

		var name = m[1].trim();
		var p = m[2].trim().split(/\s+/).map(function(v) { return +v || 0; });

		if (!name || name == 'lo')
			continue;

		rows[name] = {
			time: Date.now() / 1000,
			rx: p[0] || 0,
			rxErrors: p[2] || 0,
			rxDrops: p[3] || 0,
			tx: p[8] || 0,
			txErrors: p[10] || 0,
			txDrops: p[11] || 0
		};
	}

	return rows;
}

function parseProcStat(text) {
	var line = ((text || '').split(/\n/).filter(function(row) { return row.indexOf('cpu ') === 0; })[0] || '').trim();
	var p = line.split(/\s+/).slice(1).map(function(v) { return +v || 0; });
	var idle = (p[3] || 0) + (p[4] || 0);
	var total = 0;

	for (var i = 0; i < p.length; i++)
		total += p[i];

	return { total: total, idle: idle };
}

function cpuCoreCount(stat, cpuinfo) {
	var cores = {};
	String(cpuinfo || '').split(/\n/).forEach(function(row) {
		var match = row.match(/^core\s*:\s*(\d+)/);
		if (match)
			cores[match[1]] = true;
	});
	return Object.keys(cores).length || (String(stat || '').match(/^cpu\d+\s/gm) || []).length || 1;
}

function parseMem(info) {
	info = info || {};

	var total = info.memory && info.memory.total || info.memtotal || 0;
	var free = info.memory && (info.memory.free || info.memory.available) || info.memfree || 0;
	var cached = info.memory && info.memory.cached || 0;
	var used = Math.max(0, total - free);

	return {
		total: total,
		used: used,
		free: free,
		cached: cached,
		percent: total ? Math.round((used / total) * 100) : 0
	};
}

function pushPoint(series, value) {
	series.push(isNaN(value) ? 0 : value);

	if (series.length > maxPoints)
		series.splice(0, series.length - maxPoints);
}

function prettyBand(value, fallback) {
	value = String(value || fallback || '').toLowerCase();

	if (value == '2g' || value == '2.4ghz' || value == '2.4 ghz')
		return '2.4 GHz';
	if (value == '5g' || value == '5ghz' || value == '5 ghz')
		return '5 GHz';
	if (value == '6g' || value == '6ghz' || value == '6 ghz')
		return '6 GHz';

	return fallback || value || '-';
}

function radioChannel(radio) {
	var cfg = radio && radio.config || {};
	var channel = radio && (radio.channel || radio.frequency) || cfg.channel || '-';

	return String(channel) == 'auto' ? '-' : channel;
}

function surveyUtilizationMap(text) {
	var map = {};
	var current = {};
	var lines = (text || '').split(/\n/);

	function store(ifname) {
		var sample = current[ifname];

		if (!sample || !sample.time)
			return;

		if (!map[ifname] || sample.inUse || !map[ifname].inUse)
			map[ifname] = sample;
	}

	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		var ifaceMatch = line.match(/^interface\s+(\S+)/);
		var ifname = ifaceMatch && ifaceMatch[1];

		if (!ifname)
			continue;

		if (/Survey data from/.test(line)) {
			store(ifname);
			current[ifname] = { time: 0, busy: 0, inUse: false };
			continue;
		}

		if (!current[ifname])
			continue;

		var timeMatch = line.match(/channel (?:active )?time:\s*(\d+)/);
		var busyMatch = line.match(/channel (?:busy time|time busy):\s*(\d+)/);
		var frequencyMatch = line.match(/frequency:\s*(\d+)/);

		if (timeMatch)
			current[ifname].time = +timeMatch[1] || 0;
		if (busyMatch)
			current[ifname].busy = +busyMatch[1] || 0;
		if (frequencyMatch)
			current[ifname].frequency = +frequencyMatch[1] || 0;
		if (/\[in use\]/.test(line))
			current[ifname].inUse = true;
	}

	Object.keys(current).forEach(store);

	Object.keys(map).forEach(function(ifname) {
		var row = map[ifname];
		row.utilization = row.time ? Math.round(Math.max(0, Math.min(100, (row.busy || 0) * 100 / row.time))) : null;
	});

	return map;
}

function channelUtilization(row, survey) {
	var surveyed = survey && row.ifname && survey[row.ifname] && survey[row.ifname].utilization;

	if (surveyed != null)
		return surveyed;

	return null;
}

function channelFromFrequency(frequency) {
	var mhz = Number(frequency);

	if (mhz == 2484)
		return 14;
	if (mhz >= 2412 && mhz <= 2472)
		return Math.round((mhz - 2407) / 5);
	if (mhz >= 5000 && mhz <= 5895)
		return Math.round((mhz - 5000) / 5);
	if (mhz >= 5955 && mhz <= 7115)
		return Math.round((mhz - 5950) / 5);

	return null;
}

function surveyedChannel(row, survey) {
	var sample = survey && row.ifname ? survey[row.ifname] : null;
	var channel = sample && channelFromFrequency(sample.frequency);

	return channel != null ? channel : row.channel;
}

function counterRows(payload, counters) {
	var rows = [];
	var runtime = payload.wireless && payload.wireless.runtime || {};

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];
		var band = prettyBand(radio.config && radio.config.band, radioName == 'wifi1' ? '2.4 GHz' : '5 GHz');

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var cfg = iface.config || {};
			var ifname = iface.ifname || iface.name || iface.device;

			if (!ifname || !counters[ifname])
				continue;

			rows.push({
				ifname: ifname,
				name: '%s (%s)'.format(cfg.ssid || iface.ssid || _('SSID'), band),
				band: band
			});
		}
	});

	rows.sort(function(a, b) {
		return a.name.localeCompare(b.name);
	});

	return rows;
}

function lanTrafficInterface(payload, counters) {
	var interfaces = payload.interfaces || {};
	var lan = interfaces.lan || {};
	var ifname = lan.l3_device || lan.device || 'br-lan';

	return counters[ifname] ? ifname : (counters['br-lan'] ? 'br-lan' : ifname);
}

function wirelessRows(payload) {
	var rows = [];
	var runtime = payload.wireless && payload.wireless.runtime || {};
	var survey = surveyUtilizationMap(payload.wireless_survey);

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var cfg = iface.config || {};
			var stations = iface.stations || iface.assoclist || iface.associations || [];
			var count = Array.isArray(stations) ? stations.length : Object.keys(stations || {}).length;

			rows.push({
				ifname: iface.ifname || iface.name || iface.device,
				band: prettyBand(radio.config && radio.config.band, radioName == 'wifi1' ? '2.4 GHz' : '5 GHz'),
				channel: radioChannel(radio),
				ssid: cfg.ssid || iface.ssid || '-',
				clients: count,
				utilization: 0
			});
		}
	});

	for (var r = 0; r < rows.length; r++)
		rows[r].utilization = channelUtilization(rows[r], survey);

	for (var s = 0; s < rows.length; s++)
		rows[s].channel = surveyedChannel(rows[s], survey);

	return rows;
}

function stationList(stations) {
	if (Array.isArray(stations))
		return stations;

	return Object.keys(stations || {}).map(function(mac) {
		var row = stations[mac] || {};
		row.mac = row.mac || mac;
		return row;
	});
}

function parseWirelessStations(text) {
	var map = {};
	var currentIface = null;
	var currentMac = null;
	var lines = String(text || '').split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var line = lines[i].trim();
		var prefix = line.match(/^interface\s+(\S+)\s+(.*)$/);

		if (prefix) {
			currentIface = prefix[1];
			line = prefix[2];
		}

		var station = line.match(/^Station\s+([0-9a-f:]{17})/i);
		var hostapdStation = line.match(/^([0-9a-f:]{17})$/i);

		if (station || hostapdStation) {
			currentMac = (station ? station[1] : hostapdStation[1]).toUpperCase();
			map[currentMac] = map[currentMac] || { associated: false };
			map[currentMac].ifname = currentIface || map[currentMac].ifname || '';
			continue;
		}

		if (!currentMac)
			continue;

		if (/^flags=/.test(line) && line.indexOf('[ASSOC]') > -1 && line.indexOf('[AUTHORIZED]') > -1)
			map[currentMac].associated = true;

		var fields = [
			[ 'signal', /^signal=(-?\d+)/ ],
			[ 'rx_bytes', /^rx_bytes=(\d+)/ ],
			[ 'tx_bytes', /^tx_bytes=(\d+)/ ],
			[ 'tx_packets', /^tx_packets=(\d+)/ ],
			[ 'tx_retries', /^tx_retries=(\d+)/ ]
		];

		for (var f = 0; f < fields.length; f++) {
			var match = line.match(fields[f][1]);
			if (match)
				map[currentMac][fields[f][0]] = +match[1];
		}
	}

	return map;
}

function collectStations(payload) {
	var rows = [];
	var seen = {};
	var ifaceMeta = {};
	var runtime = payload.wireless && payload.wireless.runtime || {};
	var stationDump = parseWirelessStations(payload.wireless_stations);
	var identities = payload.client_identities || {};
	var identitiesByMac = {};

	Object.keys(identities).forEach(function(mac) {
		identitiesByMac[mac.toUpperCase()] = identities[mac] || {};
	});

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];
		var band = prettyBand(radio.config && radio.config.band, radioName);

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var cfg = iface.config || {};
			var stations = stationList(iface.stations || iface.assoclist || iface.associations);
			var ifname = iface.ifname || iface.name || iface.device || '';
			var ssid = cfg.ssid || iface.ssid || ifname || '-';
			ifaceMeta[ifname] = { ssid: ssid, band: band };

			for (var s = 0; s < stations.length; s++) {
				var sta = stations[s] || {};
				var mac = (sta.mac || sta.macaddr || '').toUpperCase();
				var identity = identitiesByMac[mac] || {};
				var dump = stationDump[mac] || {};
				var bytes = (dump.rx_bytes || sta.rx_bytes || 0) + (dump.tx_bytes || sta.tx_bytes || 0);

				if (!mac || seen[mac])
					continue;

				seen[mac] = true;
				rows.push({
					name: identity.hostname || sta.hostname || sta.host || _('Unknown client'),
					ip: identity.ipAddress || sta.ip || sta.ipaddr || '-',
					mac: mac,
					ssid: ssid,
					band: band,
					bytes: bytes
				});
			}
		}
	});

	Object.keys(stationDump).forEach(function(mac) {
		var sta = stationDump[mac] || {};
		var identity = identitiesByMac[mac] || {};
		var meta = ifaceMeta[sta.ifname] || {};

		if (seen[mac] || sta.associated === false)
			return;

		rows.push({
			name: identity.hostname || _('Unknown client'),
			ip: identity.ipAddress || '-',
			mac: mac,
			ssid: meta.ssid || sta.ifname || '-',
			band: meta.band || '-',
			bytes: (sta.rx_bytes || 0) + (sta.tx_bytes || 0)
		});
	});

	rows.sort(function(a, b) { return b.bytes - a.bytes; });
	return rows.slice(0, 5);
}

function wifiRetryRate(payload) {
	var stations = parseWirelessStations(payload.wireless_stations);
	var packets = 0;
	var retries = 0;
	var reported = false;

	Object.keys(stations).forEach(function(mac) {
		var station = stations[mac] || {};
		if (station.tx_retries == null)
			return;
		reported = true;
		packets += station.tx_packets || 0;
		retries += station.tx_retries || 0;
	});

	return reported && packets ? Math.max(0, Math.min(100, retries * 100 / packets)) : null;
}

function drawLineChart(canvas, series, colors, options) {
	if (!canvas)
		return;

	options = options || {};

	var ctx = canvas.getContext('2d');
	var rect = canvas.getBoundingClientRect();
	var dpr = window.devicePixelRatio || 1;
	var width = Math.max(420, Math.floor(rect.width));
	var height = +canvas.getAttribute('data-height') || 230;
	var padLeft = 24;
	var padRight = 24;
	var padTop = 28;
	var padBottom = options.axes ? 48 : 34;
	var max = 1;
	var tickWidth = 0;
	var tickGap = 12;

	if (canvas.width != width * dpr || canvas.height != height * dpr) {
		canvas.width = width * dpr;
		canvas.height = height * dpr;
		canvas.style.height = height + 'px';
		ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
	}

	for (var s = 0; s < series.length; s++)
		for (var p = 0; p < series[s].length; p++)
			max = Math.max(max, series[s][p]);

	max *= 1.18;

	if (options.axes) {
		ctx.font = '11px sans-serif';
		[ fmtRate(max), fmtRate(max / 2), '0 B/s' ].forEach(function(label) {
			tickWidth = Math.max(tickWidth, ctx.measureText(label).width);
		});
		padLeft = Math.max(64, Math.ceil(tickWidth + tickGap + 8));
	}

	ctx.clearRect(0, 0, width, height);
	ctx.strokeStyle = '#eee2db';
	ctx.lineWidth = 1;

	for (var g = 0; g < 3; g++) {
		var y = padTop + ((height - padTop - padBottom) / 2) * g;
		ctx.beginPath();
		ctx.moveTo(padLeft, y);
		ctx.lineTo(width - padRight, y);
		ctx.stroke();
	}

	if (options.axes) {
		var pointCount = Math.max(series[0] ? series[0].length : 0, series[1] ? series[1].length : 0);
		var elapsed = Math.max(pollInterval, (pointCount - 1) * pollInterval);

		ctx.fillStyle = '#80616a';
		ctx.font = '11px sans-serif';
		ctx.textBaseline = 'middle';
		ctx.textAlign = 'right';
		ctx.fillText(fmtRate(max), padLeft - tickGap, padTop);
		ctx.fillText(fmtRate(max / 2), padLeft - tickGap, padTop + (height - padTop - padBottom) / 2);
		ctx.fillText('0 B/s', padLeft - tickGap, height - padBottom);

		ctx.textBaseline = 'top';
		ctx.textAlign = 'left';
		ctx.fillText(_('%ds ago').format(elapsed), padLeft, height - padBottom + 10);
		ctx.textAlign = 'center';
		ctx.fillText(_('%ds ago').format(Math.round(elapsed / 2)), (padLeft + width - padRight) / 2, height - padBottom + 10);
		ctx.textAlign = 'right';
		ctx.fillText(_('Now'), width - padRight, height - padBottom + 10);

		ctx.textAlign = 'center';
		ctx.textBaseline = 'bottom';
		ctx.fillText(_('Time'), (padLeft + width - padRight) / 2, height - 1);
	}

	for (var i = 0; i < series.length; i++) {
		if (options.fill && series[i].length) {
			ctx.fillStyle = colors[i] + (i === 0 ? '20' : '16');
			ctx.beginPath();
			ctx.moveTo(padLeft, height - padBottom);

			for (var f = 0; f < series[i].length; f++) {
				var fillX = padLeft + (width - padLeft - padRight) * (f / Math.max(1, maxPoints - 1));
				var fillY = height - padBottom - ((height - padTop - padBottom) * (series[i][f] / max));
				ctx.lineTo(fillX, fillY);
			}

			var lastX = padLeft + (width - padLeft - padRight) * ((series[i].length - 1) / Math.max(1, maxPoints - 1));
			ctx.lineTo(lastX, height - padBottom);
			ctx.closePath();
			ctx.fill();
		}

		ctx.strokeStyle = colors[i];
		ctx.lineWidth = 2.5;
		ctx.beginPath();

		for (var j = 0; j < series[i].length; j++) {
			var x = padLeft + (width - padLeft - padRight) * (j / Math.max(1, maxPoints - 1));
			var y2 = height - padBottom - ((height - padTop - padBottom) * (series[i][j] / max));

			if (j === 0)
				ctx.moveTo(x, y2);
			else
				ctx.lineTo(x, y2);
		}

		ctx.stroke();
	}
}

function hero(refresh) {
	return E('section', { 'class': 'stats-v3-hero status-page-hero' }, [
		E('div', {}, [
			E('h1', {}, _('Traffic & Radio Metrics'))
		]),
		E('div', { 'class': 'stats-v3-refresh-box status-page-actions' }, [
			E('button', {
				'class': 'stats-v3-refresh status-page-refresh',
				'type': 'button',
				'click': refresh
			}, _('Refresh')),
			E('small', { 'class': 'status-page-updated', 'id': 'stats-updated' }, updatedLabel())
		])
	]);
}

function healthStrip() {
	return E('section', { 'class': 'stats-health-strip' }, [
		E('strong', { 'id': 'stats-health-state' }, _('Collecting telemetry...')),
		E('span', { 'id': 'stats-health-load' }, _('Load collecting...')),
		E('span', { 'id': 'stats-health-retry' }, _('Wi-Fi retry rate collecting...')),
		E('span', { 'id': 'stats-health-errors' }, _('Interface errors collecting...'))
	]);
}

function metricCard(label, valueId, note, sideId) {
	return E('article', { 'class': 'stats-metric-card' }, [
		E('small', {}, label),
		E('strong', { 'id': valueId, 'class': 'tech' }, '-'),
		E('div', { 'class': 'stats-metric-foot' }, [
			E('span', {}, note),
			E('em', { 'id': sideId }, '')
		])
	]);
}

function resourceCard(type, title, note, valueId, detailId, badgeId) {
	return E('article', { 'class': 'stats-resource-card stats-resource-' + type }, [
		E('div', { 'class': 'stats-card-head' }, [
			E('div', {}, [
				E('h2', {}, title),
				E('p', {}, note)
			]),
			E('span', { 'id': badgeId, 'class': 'stats-pill' }, _('Normal'))
		]),
		E('div', { 'class': 'stats-resource-value' }, [
			E('strong', { 'id': valueId }, '0%'),
			E('span', { 'id': detailId }, '')
		]),
		E('div', { 'class': 'stats-bar' }, E('span', { 'id': valueId + '-bar' })),
		E('canvas', { 'id': valueId + '-chart', 'data-height': '92' }),
		E('div', { 'class': 'stats-card-foot' }, [
			E('span', { 'id': valueId + '-left' }, ''),
			E('span', { 'id': valueId + '-middle' }, ''),
			E('span', { 'id': valueId + '-right' }, '')
		])
	]);
}

function liveTrafficCard() {
	return E('section', { 'class': 'stats-live-card' }, [
		E('div', { 'class': 'stats-card-head' }, [
			E('div', {}, [
				E('h2', {}, _('Live Traffic')),
				E('p', {}, _('RX and TX on one shared scale.')),
				E('p', { 'class': 'stats-live-source' }, [
					E('strong', {}, _('Monitoring: ')),
					_('LAN')
				])
			]),
			E('div', { 'class': 'stats-legend' }, [
				E('span', { 'class': 'rx' }, _('RX')),
				E('span', { 'class': 'tx' }, _('TX'))
			])
		]),
		E('div', { 'class': 'stats-live-chart' }, [
			E('span', { 'class': 'stats-live-y-label', 'aria-hidden': 'true' }, _('Throughput (B/s)')),
			E('canvas', { 'id': 'stats-live-traffic', 'data-height': '260' })
		]),
		E('div', { 'class': 'stats-retry-row' }, [
			E('span', {}, _('Wi-Fi retry rate')),
			E('strong', { 'id': 'stats-retry-rate' }, _('Collecting...'))
		]),
		E('div', { 'class': 'stats-bar retry' }, E('span', { 'id': 'stats-retry-bar' }))
	]);
}

function topClientRows(clients) {
	return clients.length ? clients.map(function(client) {
		var initials = String(client.name || 'CL').replace(/[^A-Za-z0-9]/g, '').substr(0, 2).toUpperCase() || 'CL';

		return E('div', { 'class': 'stats-client-row' }, [
			E('span', { 'class': 'stats-avatar' }, initials),
			E('span', {}, [
				E('strong', {}, client.name),
				E('small', {}, client.ip != '-' ? client.ip : client.mac)
			]),
			E('em', { 'class': 'tech' }, fmtBytes(client.bytes || 0))
		]);
	}) : [ E('div', { 'class': 'client-empty' }, _('No active clients')) ];
}

function topClientsCard(clients) {
	return E('section', { 'class': 'stats-side-card' }, [
		E('h2', {}, _('Top Clients by Traffic')),
		E('p', {}, _('Associated clients ranked by session traffic.')),
		E('div', { 'id': 'stats-top-clients', 'class': 'stats-client-list' }, topClientRows(clients))
	]);
}

function channelUtilizationItems(rows) {
	var bands = {};

	for (var i = 0; i < rows.length; i++) {
		var row = rows[i];
		var current = bands[row.band] || {
			band: row.band,
			channel: row.channel,
			clients: 0,
			utilization: null
		};

		current.clients += row.clients || 0;
		if (row.utilization != null)
			current.utilization = current.utilization == null ? row.utilization : Math.max(current.utilization, row.utilization);

		if (current.channel == '-' && row.channel != '-')
			current.channel = row.channel;

		bands[row.band] = current;
	}

	var bandRows = [ bands['2.4 GHz'], bands['5 GHz'], bands['6 GHz'] ].filter(function(row) { return row; });
	return bandRows.length ? bandRows.map(function(row) {
		var reported = row.utilization != null;
		var pct = reported ? Math.max(0, Math.min(100, row.utilization)) : 0;

		return E('div', { 'class': 'stats-signal-row' }, [
			E('span', {}, [
				E('strong', {}, '%s channel'.format(row.band)),
				E('small', {}, row.channel != '-' ? _('Channel %s').format(row.channel) : _('Auto channel'))
			]),
			E('div', { 'class': 'stats-channel-meter' }, [
				E('div', { 'class': 'stats-channel-bar' }, E('span', { 'style': 'width:%d%%'.format(pct) })),
				E('em', {}, reported ? '%d%%'.format(pct) : _('Not reported'))
			])
		]);
	}) : [ E('div', { 'class': 'client-empty' }, _('No wireless radios are reporting')) ];
}

function channelUtilizationCard(rows) {
	return E('section', { 'class': 'stats-side-card' }, [
		E('h2', {}, _('Channel Utilization')),
		E('p', {}, _('2.4 GHz and 5 GHz airtime usage.')),
		E('div', { 'id': 'stats-wireless-signal' }, channelUtilizationItems(rows))
	]);
}

function replaceContent(node, children) {
	if (!node)
		return;
	while (node.firstChild)
		node.removeChild(node.firstChild);
	for (var i = 0; i < children.length; i++)
		node.appendChild(children[i]);
}

function ifaceRow(row) {
	return E('div', { 'class': 'stats-v3-iface-row', 'id': 'stats-iface-' + cleanId(row.ifname) }, [
		E('strong', {}, row.name),
		E('span', { 'class': 'tech stat-rx-rate' }, '-'),
		E('span', { 'class': 'tech stat-tx-rate' }, '-'),
		E('span', { 'class': 'tech stat-errors' }, '0'),
		E('em', {}, row.band)
	]);
}

function interfaceCounters(rows) {
	return E('section', { 'class': 'stats-counters-card' }, [
		E('h2', {}, _('Interface Counters')),
		E('p', {}, _('Wireless SSID counters by radio band.')),
		E('div', { 'class': 'stats-v3-iface-table' }, [
			E('div', { 'class': 'stats-v3-iface-head' }, [
				E('span', {}, _('Wireless Network')),
				E('span', {}, _('RX')),
				E('span', {}, _('TX')),
				E('span', {}, _('Errors')),
				E('span', {}, _('Band'))
			]),
			E('div', { 'class': 'stats-v3-iface-body' }, rows.length ?
				rows.map(ifaceRow) :
				[ E('div', { 'class': 'client-empty' }, _('No interfaces are reporting counters.')) ])
		])
	]);
}

return view.extend({
	load: function() {
		return L.resolveDefault(callStatusStatistics(), {});
	},

	render: function(data) {
		statisticsGeneration++;
		var payload = envelopeData(data);
		var counters = parseProcNetDev(payload.proc_net_dev);
		var counterItems = counterRows(payload, counters);
		var state = {
			lastTraffic: counters,
			trafficIfname: lanTrafficInterface(payload, counters),
			traffic: [ [], [] ],
			cpu: [ [] ],
			mem: [ [] ],
			lastCpu: parseProcStat(payload.proc_stat),
			started: Date.now()
		};
		var page = E('div', { 'class': 'airdash stats-v3-page status-page' }, [
			hero(function() { return refresh(); }),
			healthStrip(),
			E('section', { 'class': 'stats-metric-grid' }, [
				metricCard(_('Download'), 'stats-download', _('aggregate RX rate'), 'stats-download-side'),
				metricCard(_('Upload'), 'stats-upload', _('aggregate TX rate'), 'stats-upload-side'),
				metricCard(_('Interfaces'), 'stats-ifaces', _('active now'), 'stats-ifaces-side')
			]),
			E('section', { 'class': 'stats-resource-grid' }, [
				resourceCard('cpu', _('CPU Utilisation'), _('CPU time currently in use across all cores.'), 'stats-cpu', 'stats-cpu-detail', 'stats-cpu-badge'),
				resourceCard('memory', _('Memory'), _('RAM currently in use, including cache and buffers.'), 'stats-memory', 'stats-memory-detail', 'stats-memory-badge')
			]),
			liveTrafficCard(),
			E('section', { 'class': 'stats-side-grid' }, [
				topClientsCard(collectStations(payload)),
				channelUtilizationCard(wirelessRows(payload))
			]),
			interfaceCounters(counterItems),
			E('footer', { 'class': 'status-page-footer' }, _('© AirPro Technology India Ltd. All rights reserved.'))
		]);

		var refresh = function() {
			if (document.hidden)
				return Promise.resolve();

			var generation = ++statisticsGeneration;
			var button = page.querySelector('.stats-v3-refresh');
			var updated = document.getElementById('stats-updated');

			if (button)
				button.disabled = true;
			if (updated) {
				updated.classList.remove('is-stale');
				updated.classList.add('is-loading');
				updated.textContent = _('Refreshing live data...');
			}

			return callStatusStatistics().then(function(result) {
				if (generation != statisticsGeneration)
					return;
				if (!result || result.ok === false || !result.data)
					throw new Error('Invalid statistics response');

				var nextPayload = envelopeData(result);
				var nextCounters = parseProcNetDev(nextPayload.proc_net_dev);
				var loadValues = nextPayload.system && nextPayload.system.load || [];
				var mem = parseMem(nextPayload.system);
				var cpu = parseProcStat(nextPayload.proc_stat);
				var coreCount = cpuCoreCount(nextPayload.proc_stat, nextPayload.proc_cpuinfo);
				var cpuPct = 0;
				var download = 0;
				var upload = 0;
				var errorInterfaces = 0;
				var retryRate = wifiRetryRate(nextPayload);
				var wireless = wirelessRows(nextPayload);
				var trafficRow = nextCounters[state.trafficIfname];
				var previousTrafficRow = state.lastTraffic[state.trafficIfname];

				if (trafficRow && previousTrafficRow && trafficRow.time > previousTrafficRow.time) {
					var trafficDelta = trafficRow.time - previousTrafficRow.time;
					download = Math.max(0, ((trafficRow.rx || 0) - (previousTrafficRow.rx || 0)) / trafficDelta);
					upload = Math.max(0, ((trafficRow.tx || 0) - (previousTrafficRow.tx || 0)) / trafficDelta);
				}

				if (trafficRow)
					state.lastTraffic[state.trafficIfname] = trafficRow;

				if (state.lastCpu && cpu.total > state.lastCpu.total) {
					var totalDelta = cpu.total - state.lastCpu.total;
					var idleDelta = cpu.idle - state.lastCpu.idle;
					cpuPct = Math.round(Math.max(0, Math.min(100, (1 - idleDelta / totalDelta) * 100)));
				}

				state.lastCpu = cpu;
				pushPoint(state.cpu[0], cpuPct);
				pushPoint(state.mem[0], mem.percent);

				for (var i = 0; i < counterItems.length; i++) {
					var ifname = counterItems[i].ifname;
					var row = nextCounters[ifname];
					var prev = state.lastTraffic[ifname];
					var rx = 0;
					var tx = 0;

					if (row && prev && row.time > prev.time) {
						var delta = row.time - prev.time;
						rx = Math.max(0, ((row.rx || 0) - (prev.rx || 0)) / delta);
						tx = Math.max(0, ((row.tx || 0) - (prev.tx || 0)) / delta);
					}

					if (row)
						state.lastTraffic[ifname] = row;

					if (row && ((row.rxErrors || 0) + (row.txErrors || 0)) > 0)
						errorInterfaces++;

					var rowNode = document.getElementById('stats-iface-' + cleanId(ifname));
					if (rowNode && row) {
						rowNode.querySelector('.stat-rx-rate').textContent = fmtRate(rx);
						rowNode.querySelector('.stat-tx-rate').textContent = fmtRate(tx);
						rowNode.querySelector('.stat-errors').textContent = String((row.rxErrors || 0) + (row.txErrors || 0));
					}
				}

				pushPoint(state.traffic[0], download);
				pushPoint(state.traffic[1], upload);

				document.getElementById('stats-download').textContent = fmtRate(download);
				document.getElementById('stats-upload').textContent = fmtRate(upload);
				document.getElementById('stats-ifaces').textContent = String(counterItems.length);
				document.getElementById('stats-ifaces-side').textContent = _('%d wireless networks').format(counterItems.length);
				document.getElementById('stats-download-side').textContent = _('peak %s').format(fmtRate(Math.max.apply(Math, state.traffic[0])));
				document.getElementById('stats-upload-side').textContent = _('peak %s').format(fmtRate(Math.max.apply(Math, state.traffic[1])));
				document.getElementById('stats-cpu').textContent = '%d%%'.format(cpuPct);
				document.getElementById('stats-cpu-detail').textContent = _('of %d cores').format(coreCount);
				document.getElementById('stats-cpu-bar').style.width = Math.min(100, cpuPct) + '%';
				document.getElementById('stats-cpu-badge').textContent = cpuPct > 85 ? _('High') : _('Normal');
				document.getElementById('stats-cpu-left').textContent = _('1m avg: %s').format(loadValues.length ? fmtLoad((loadValues[0] || 0) / 65536) : '-');
				document.getElementById('stats-cpu-middle').textContent = _('5m avg: %s').format(loadValues.length ? fmtLoad((loadValues[1] || 0) / 65536) : '-');
				document.getElementById('stats-cpu-right').textContent = _('15m avg: %s').format(loadValues.length ? fmtLoad((loadValues[2] || 0) / 65536) : '-');
				document.getElementById('stats-memory').textContent = '%d%%'.format(mem.percent);
				document.getElementById('stats-memory-detail').textContent = _('of %s').format(fmtBytes(mem.total));
				document.getElementById('stats-memory-bar').style.width = Math.min(100, mem.percent) + '%';
				document.getElementById('stats-memory-badge').textContent = mem.percent > 80 ? _('Elevated') : _('Normal');
				document.getElementById('stats-memory-left').textContent = _('Used: %s').format(fmtBytes(mem.used));
				document.getElementById('stats-memory-middle').textContent = _('Free: %s').format(fmtBytes(mem.free));
				document.getElementById('stats-memory-right').textContent = _('Cache: %s').format(fmtBytes(mem.cached));
				document.getElementById('stats-health-load').textContent = _('Load %s / %d cores').format(loadValues.length ? fmtLoad((loadValues[0] || 0) / 65536) : '-', coreCount);
				document.getElementById('stats-health-state').textContent = errorInterfaces ? _('Attention required') : _('Live telemetry');
				document.getElementById('stats-health-retry').textContent = retryRate == null ? _('Wi-Fi retry rate not reported') : _('Wi-Fi retry rate %s').format('%.1f%%'.format(retryRate));
				document.getElementById('stats-health-errors').textContent = _('%d interfaces reporting errors').format(errorInterfaces);
				document.getElementById('stats-updated').textContent = updatedLabel();
				document.getElementById('stats-retry-rate').textContent = retryRate == null ? _('Not reported') : '%.1f%%'.format(retryRate);
				document.getElementById('stats-retry-bar').style.width = (retryRate == null ? 0 : Math.min(100, retryRate)) + '%';
				replaceContent(document.getElementById('stats-top-clients'), topClientRows(collectStations(nextPayload)));
				replaceContent(document.getElementById('stats-wireless-signal'), channelUtilizationItems(wireless));

				drawLineChart(document.getElementById('stats-live-traffic'), state.traffic, [ '#21195f', '#ff7a1a' ], { axes: true, fill: true });
				drawLineChart(document.getElementById('stats-cpu-chart'), state.cpu, [ '#f58634' ]);
				drawLineChart(document.getElementById('stats-memory-chart'), state.mem, [ '#17084d' ]);
			}).catch(function() {
				if (generation == statisticsGeneration && updated) {
					updated.classList.remove('is-loading');
					updated.classList.add('is-stale');
					updated.textContent = _('Update failed - showing last successful data');
				}
			}).finally(function() {
				if (button && button.isConnected)
					button.disabled = false;
			});
		};

		poll.add(refresh, pollInterval);

		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
