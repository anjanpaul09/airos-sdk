'use strict';
'require view';
'require poll';
'require rpc';

var callStatusSummary = rpc.declare({ object: 'airui.status', method: 'summary', expect: { '': {} } });
var callStatusClients = rpc.declare({ object: 'airui.status', method: 'clients', expect: { '': {} } });

var lastCpu = null;
var dashboardGeneration = 0;
var dashboardPollRegistered = false;

function dashboardData() {
	return Promise.all([ callStatusSummary(), callStatusClients() ]);
}

function validEnvelope(response) {
	return response && response.ok !== false && response.data;
}

function updatedLabel() {
	return _('Updated at %s').format(new Date().toLocaleTimeString());
}

function resolveFast(promise, fallback) {
	return Promise.race([
		L.resolveDefault(promise, fallback),
		new Promise(function(resolve) {
			window.setTimeout(function() { resolve(fallback); }, 2500);
		})
	]);
}

function envelopeData(response) {
	return response && response.ok !== false && response.data ? response.data : {};
}

function uciValues(payload, config) {
	var root = payload && payload[config || 'uci'] || {};
	return root.values || root;
}

function isWifiIface(section) {
	return section && (section['.type'] == 'wifi-iface' || section.type == 'wifi-iface' || section.device);
}

function wifiSections(payload) {
	var values = uciValues(payload.wireless || {}, 'uci');
	var rows = [];

	Object.keys(values || {}).forEach(function(name) {
		var row = values[name] || {};

		if (isWifiIface(row)) {
			row.section = row.section || name;
			rows.push(row);
		}
	});

	rows.sort(function(a, b) {
		var rank = { wlan1: 0, wlan2: 1 };
		return (rank[a.section] != null ? rank[a.section] : 50) - (rank[b.section] != null ? rank[b.section] : 50);
	});

	return rows;
}

function runtimeClientCount(runtime) {
	var seen = {};

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

		for (var i = 0; i < ifaces.length; i++) {
			var stations = ifaces[i].stations || ifaces[i].assoclist || ifaces[i].associations || [];
			var list = stationList(stations);

			for (var j = 0; j < list.length; j++) {
				var mac = (list[j].mac || list[j].macaddr || '').toUpperCase();

				if (mac)
					seen[mac] = true;
			}
		}
	});

	return Object.keys(seen).length;
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

function leaseMap(leases) {
	var map = {};

	for (var i = 0; i < (leases || []).length; i++) {
		var lease = leases[i] || {};
		var ip = lease.ipaddr || lease.ip;
		var mac = (lease.macaddr || lease.mac || '').toUpperCase();
		var row = {
			host: lease.hostname || lease.host || '-',
			ip: ip || '-',
			mac: mac || '-'
		};

		if (ip)
			map[ip] = row;

		if (mac)
			map[mac] = row;
	}

	return map;
}

function parseWirelessStations(text) {
	var map = {};
	var currentIface = null;
	var currentMac = null;
	var lines = (text || '').split(/\n/);

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
			map[currentMac] = map[currentMac] || {};
			map[currentMac].ifname = currentIface || map[currentMac].ifname || '';
			continue;
		}

		if (!currentMac)
			continue;

		var signal = line.match(/^\s*signal:\s*(-?\d+)/) || line.match(/^\s*signal=(-?\d+)/);
		var rxBytes = line.match(/^\s*rx_bytes=(\d+)/);
		var txBytes = line.match(/^\s*tx_bytes=(\d+)/);

		if (signal)
			map[currentMac].signal = +signal[1];
		if (rxBytes)
			map[currentMac].rx_bytes = +rxBytes[1];
		if (txBytes)
			map[currentMac].tx_bytes = +txBytes[1];
	}

	return map;
}

function stationDumpCount(payload) {
	return Object.keys(parseWirelessStations(payload.wireless_stations)).length;
}

function topClients(payload, leases) {
	var rows = [];
	var seen = {};
	var runtime = payload.wireless && payload.wireless.runtime || {};
	var leasesByKey = leaseMap(leases);
	var stationDump = parseWirelessStations(payload.wireless_stations);
	var identities = payload.client_identities || {};
	var identitiesByMac = {};

	Object.keys(identities).forEach(function(mac) {
		identitiesByMac[mac.toUpperCase()] = identities[mac] || {};
	});

	function add(row) {
		var key = (row.mac || '').toUpperCase() || row.ip;

		if (!key || seen[key])
			return;

		seen[key] = true;
		rows.push(row);
	}

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var cfg = iface.config || {};
			var stations = stationList(iface.stations || iface.assoclist || iface.associations);
			var ssid = cfg.ssid || iface.ssid || iface.ifname || iface.section || radioName;

			for (var j = 0; j < stations.length; j++) {
				var sta = stations[j] || {};
				var mac = (sta.mac || sta.macaddr || '').toUpperCase();
				var lease = leasesByKey[mac] || {};
				var identity = identitiesByMac[mac] || {};
				var dump = stationDump[mac] || {};
				var signal = sta.signal != null ? sta.signal : sta.rssi;
				var bytes = (dump.rx_bytes || sta.rx_bytes || 0) + (dump.tx_bytes || sta.tx_bytes || 0);

				add({
					mac: mac,
					ip: identity.ipAddress || lease.ip || sta.ip || '',
					name: identity.hostname || lease.host || sta.hostname || _('Unknown client'),
					detail: [ identity.ipAddress || lease.ip || sta.ip || '-', mac || '-' ].join(' / '),
					link: ssid,
					metric: signal != null ? '%d dBm'.format(signal) : fmtBytes(bytes),
					bytes: bytes
				});
			}
		}
	});

	Object.keys(stationDump).forEach(function(mac) {
		var dump = stationDump[mac] || {};
		var lease = leasesByKey[mac] || {};
		var identity = identitiesByMac[mac] || {};
		var bytes = (dump.rx_bytes || 0) + (dump.tx_bytes || 0);

		add({
			mac: mac,
			ip: identity.ipAddress || lease.ip || '',
			name: identity.hostname || lease.host || _('Unknown client'),
			detail: [ identity.ipAddress || lease.ip || '-', mac ].join(' / '),
			link: dump.ifname || _('Wi-Fi'),
			metric: dump.signal != null ? '%d dBm'.format(dump.signal) : fmtBytes(bytes),
			bytes: bytes
		});
	});

	return rows.sort(function(a, b) {
		return (b.bytes || 0) - (a.bytes || 0);
	}).slice(0, 5);
}

function fmtBytes(v) {
	return '%1024.1mB'.format(v || 0);
}

function fmtUptime(seconds) {
	seconds = Math.max(0, Math.floor(seconds || 0));

	var days = Math.floor(seconds / 86400);
	var hours = Math.floor((seconds % 86400) / 3600);
	var mins = Math.floor((seconds % 3600) / 60);

	if (days)
		return '%dd %dh'.format(days, hours);

	return '%dh %dm'.format(hours, mins);
}

function cpuSnapshot(stat) {
	var line = (stat || '').split(/\n/)[0] || '';
	var p = line.trim().split(/\s+/).slice(1).map(function(v) { return +v || 0; });

	return {
		user: (p[0] || 0) + (p[1] || 0),
		kernel: p[2] || 0,
		idle: (p[3] || 0) + (p[4] || 0),
		other: (p[5] || 0) + (p[6] || 0) + (p[7] || 0)
	};
}

function cpuUsed(stat) {
	var current = cpuSnapshot(stat);
	var prev = lastCpu || current;
	var busy = Math.max(0, current.user - prev.user) +
		Math.max(0, current.kernel - prev.kernel) +
		Math.max(0, current.other - prev.other);
	var idle = Math.max(0, current.idle - prev.idle);
	var total = busy + idle;

	lastCpu = current;

	return total > 0 ? Math.max(0, Math.min(100, Math.round(busy * 100 / total))) : 0;
}

function kpi(label, value, subtext, active) {
	return E('div', { 'class': 'card kpi' }, [
		active ? E('span', { 'class': 'status-dot is-active', 'title': _('Online') }) : '',
		E('div', { 'class': 'label' }, label),
		E('div', { 'class': 'value' }, value || '-'),
		E('div', { 'class': 'sub' }, subtext || '')
	]);
}

function statusFooter() {
	return E('footer', { 'class': 'status-page-footer' }, _('© AirPro Technology India Ltd. All rights reserved.'));
}

function uplinkSummary(payload) {
	var ifaces = payload.interfaces || {};
	var uplink = ifaces.wan && ifaces.wan.available !== false ? ifaces.wan : ifaces.lan || {};
	var up = uplink.up !== false && uplink.available !== false;

	return {
		up: up,
		value: up ? _('1 Gbps / Full Duplex') : _('Down'),
		subtext: up ? _('Link up') : _('Link down')
	};
}

function donutCard(id, title, percent, note, rows, navy) {
	return E('div', { 'class': 'card metric-card', 'id': id }, [
		E('div', { 'class': 'metric-head' }, [
			E('div', { 'class': 'metric-title' }, title),
			E('div', { 'class': 'metric-note' }, note || '')
		]),
		E('div', { 'class': 'metric-body' }, [
			E('div', {
				'class': navy ? 'donut navy' : 'donut',
				'style': '--p:%d'.format(percent || 0)
			}, [
				E('div', { 'class': 'donut-center' }, [
					E('strong', {}, '%d%%'.format(percent || 0)),
					E('span', {}, _('Used'))
				])
			]),
			E('div', { 'class': 'legend' }, rows.map(function(row) {
				return E('div', { 'class': 'legend-row' }, [
					E('div', { 'class': 'legend-left' }, [
						E('span', { 'class': row[2] || 'bullet' }),
						row[0]
					]),
					E('strong', {}, row[1])
				]);
			}))
		])
	]);
}

function detailCard(title, rows) {
	var children = [
		E('div', { 'class': 'detail-head' }, title),
	];

	for (var i = 0; i < rows.length; i++) {
		children.push(E('div', { 'class': 'table-row' }, [
			E('span', { 'class': 'k' }, rows[i][0]),
			E('span', { 'class': rows[i][2] || 'v' }, rows[i][1] || '-')
		]));
	}

	return E('div', { 'class': 'card detail-card' }, children);
}

function topClientsCard(rows) {
	var children = [ E('div', { 'class': 'detail-head' }, _('Top 5 Clients')) ];

	if (!rows.length) {
		children.push(E('div', { 'class': 'table-row' }, [
			E('span', { 'class': 'k' }, _('No active clients')),
			E('span', { 'class': 'v muted' }, '-')
		]));
		return E('div', { 'class': 'card detail-card top-clients-card' }, children);
	}

	for (var i = 0; i < rows.length; i++) {
		children.push(E('div', { 'class': 'table-row' }, [
			E('span', { 'class': 'k' }, [
				E('strong', {}, rows[i].name),
				E('small', {}, rows[i].detail)
			]),
			E('span', { 'class': 'v' }, [
				E('strong', {}, rows[i].link),
				E('small', {}, rows[i].metric)
			])
		]));
	}

	return E('div', { 'class': 'card detail-card top-clients-card' }, children);
}

function updateDonut(root, percent, rows) {
	if (!root)
		return;

	var donut = root.querySelector('.donut');
	var center = root.querySelector('.donut-center strong');
	var legend = root.querySelector('.legend');

	if (donut)
		donut.style.setProperty('--p', percent || 0);

	if (center)
		center.textContent = '%d%%'.format(percent || 0);

	if (legend && rows) {
		legend.innerHTML = '';
		for (var i = 0; i < rows.length; i++) {
			legend.appendChild(E('div', { 'class': 'legend-row' }, [
				E('div', { 'class': 'legend-left' }, [
					E('span', { 'class': rows[i][2] || 'bullet' }),
					rows[i][0]
				]),
				E('strong', {}, rows[i][1])
			]));
		}
	}
}

function buildDashboardPage(data) {
		var payload = envelopeData(Array.isArray(data) ? data[0] : data);
		var clientsPayload = envelopeData(Array.isArray(data) ? data[1] : data);
		var board = payload.board || {};
		var info = payload.system || {};
		var mem = info.memory || {};
		var radios = wifiSections(payload);
		var leases = payload.leases && Array.isArray(payload.leases.dhcp_leases) ? payload.leases.dhcp_leases : [];
		var total = mem.total || 0;
		var free = mem.free || 0;
		var used = Math.max(0, total - free);
		var memPct = total ? Math.round(used * 100 / total) : 0;
		var cpuPct = cpuUsed(payload.proc_stat);
		var activeRadios = 0;
		var associatedClients = Math.max(
			runtimeClientCount(clientsPayload.wireless && clientsPayload.wireless.runtime),
			stationDumpCount(clientsPayload)
		);

		for (var i = 0; i < radios.length; i++) {
			if (radios[i].disabled != '1')
				activeRadios++;
		}

		var clients = associatedClients;
		var clientLeases = clientsPayload.leases && Array.isArray(clientsPayload.leases.dhcp_leases) ? clientsPayload.leases.dhcp_leases : leases;
		var clientRows = topClients(clientsPayload, clientLeases);
		var uplink = uplinkSummary(payload);
		var model = 'AirPro AP520';
		var target = board.release && board.release.target || board.target || 'ramips/mt7621';
		var version = board.release && board.release.version || '24.10.0';
		var load = info.load && info.load.length ? (info.load[0] / 65536).toFixed(2) : '0.00';
		var currentMode = payload.mode && payload.mode.current || _('Standalone');

		var page;
		var refresh = function() {
			if (document.hidden)
				return Promise.resolve();

			var generation = ++dashboardGeneration;
			var button = page && page.querySelector('.status-page-refresh');
			var updated = page && page.querySelector('.status-page-updated');

			if (button)
				button.disabled = true;

			return dashboardData().then(function(result) {
				if (generation != dashboardGeneration)
					return;
				if (!validEnvelope(result[0]) || !validEnvelope(result[1]))
					throw new Error('Invalid dashboard response');

				var nextPage = buildDashboardPage(result);
				if (page && page.parentNode)
					page.parentNode.replaceChild(nextPage, page);
				page = nextPage;
			}).catch(function(error) {
				if (generation == dashboardGeneration && updated)
					updated.textContent = _('Update failed: %s').format(error && error.message ? error.message : String(error));
				if (window.console && console.error)
					console.error('AirUI dashboard refresh failed', error);
			}).finally(function() {
				if (button && button.isConnected)
					button.disabled = false;
			});
		};

		page = E('div', { 'class': 'airdash status-page' }, [
			E('section', { 'class': 'status-page-hero' }, [
				E('div', { 'class': 'status-page-copy' }, [
					E('span', { 'class': 'status-page-eyebrow' }, _('Status')),
					E('h1', {}, _('Dashboard')),
					E('p', {}, _('Overview of system performance, connectivity, and hardware telemetry for %s.').format(model))
				]),
				E('div', { 'class': 'status-page-actions' }, [
					E('button', { 'class': 'status-page-refresh', 'type': 'button', 'click': refresh }, _('Refresh')),
					E('small', { 'class': 'status-page-updated' }, updatedLabel())
				])
			]),
			E('section', { 'class': 'kpis' }, [
				kpi(_('Uplink'), uplink.value, uplink.subtext, uplink.up),
				kpi(_('Clients'), String(clients), _('Wi-Fi associated'), clients > 0),
				kpi(_('Wireless Interfaces'), _('%d active of %d').format(activeRadios, radios.length || 0), _('Configured wireless interfaces'), activeRadios > 0),
				kpi(_('Uptime'), fmtUptime(info.uptime), _('Since last boot'), false),
				kpi(_('Current Mode'), currentMode, _('Local management'), false)
			]),
			E('section', { 'class': 'metrics' }, [
				donutCard('airdash-cpu', _('CPU Utilisation'), cpuPct, _('Load: %s').format(load), [
					[ _('Used'), '%d%%'.format(cpuPct), 'bullet' ],
					[ _('Idle'), '%d%%'.format(100 - cpuPct), 'bullet light' ]
				], false),
				donutCard('airdash-memory', _('Memory Utilisation'), memPct, _('Total: %s').format(fmtBytes(total)), [
					[ _('Used'), fmtBytes(used), 'bullet navy' ],
					[ _('Free'), fmtBytes(free), 'bullet light' ]
				], true)
			]),
			E('section', { 'class': 'details' }, [
				detailCard(_('System Details'), [
					[ _('Firmware'), version ],
					[ _('Platform'), target ],
					[ _('Current Mode'), currentMode ],
					[ _('Model Name'), model ]
				]),
				detailCard(_('Storage Devices'), [
					[ _('USB Interface'), _('None'), 'v muted' ],
					[ _('Disk Partition'), _('Not mounted'), 'v muted' ],
					[ _('Health'), _('Ready'), 'v good' ],
					[ _('Status'), _('No connected devices') ]
				])
			]),
			E('section', { 'class': 'details dashboard-bottom' }, [
				topClientsCard(clientRows)
			]),
			statusFooter()
		]);

		if (!dashboardPollRegistered) {
			dashboardPollRegistered = true;
			poll.add(refresh, 5);
		}

		return page;
	}

var dashboardView = view.extend({
	load: function() {
		dashboardGeneration++;
		dashboardPollRegistered = false;
		return Promise.all([
			resolveFast(callStatusSummary(), {}),
			resolveFast(callStatusClients(), {})
		]);
	},

	render: buildDashboardPage,

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

return dashboardView;
