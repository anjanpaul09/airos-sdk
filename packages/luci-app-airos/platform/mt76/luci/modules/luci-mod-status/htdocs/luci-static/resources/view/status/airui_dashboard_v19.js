'use strict';
'require view';
'require poll';
'require rpc';

var callStatusSnapshot = rpc.declare({ object: 'airui.status', method: 'snapshot', expect: { '': {} } });
var callUciAircnms = rpc.declare({ object: 'uci', method: 'get', params: [ 'config' ], expect: { 'values': {} } });
var callControllerStatus = rpc.declare({ object: 'airui.mode', method: 'controller_status', expect: { '': {} } });

var lastSerialNum = null;
var cachedVersionInfo = null;

function fetchVersionInfo() {
	if (cachedVersionInfo)
		return Promise.resolve(cachedVersionInfo);

	return L.resolveDefault(callUciAircnms('version'), null).then(function(res) {
		var values = res ? (res.values || res) : null;
		if (values) {
			for (var k in values) {
				var v = values[k];
				if (v && (v.version || v.model || v.platform)) {
					cachedVersionInfo = {
						version: v.version || null,
						model: v.model ? (v.model.indexOf('AirPro') === 0 ? v.model : 'AirPro ' + v.model) : null,
						platform: v.platform || null,
						timestamp: v.timestamp || null
					};
					return cachedVersionInfo;
				}
			}
		}
		return null;
	}).catch(function() {
		return null;
	});
}

function fetchSerialNum() {
	if (lastSerialNum)
		return Promise.resolve(lastSerialNum);

	return L.resolveDefault(callUciAircnms('aircnms'), null).then(function(res) {
		if (res) {
			var values = res.values || res;
			for (var k in values) {
				var s = values[k];
				if (s && s.serial_num && !/^X+$/.test(s.serial_num)) {
					lastSerialNum = s.serial_num;
					return s.serial_num;
				}
			}
		}
		return L.resolveDefault(callControllerStatus(), null).then(function(modeRes) {
			var s = modeRes && modeRes.data && modeRes.data.serial_num;
			if (s && !/^X+$/.test(s)) {
				lastSerialNum = s;
				return s;
			}
			return '-';
		});
	}).catch(function() {
		return '-';
	});
}

var lastCpu = null;
var dashboardGeneration = 0;
var dashboardPollRegistered = false;
var lastValidDashboardEnvelope = null;
var dashboardAutoRefreshStorageKey = 'airui.dashboard.auto_refresh';
var dashboardAutoRefreshEnabled = true;
var dashboardHeaderObserver = null;

try {
	dashboardAutoRefreshEnabled = window.localStorage.getItem(dashboardAutoRefreshStorageKey) !== 'off';
}
catch (e) {
	/* Browsers may block storage in private or restricted sessions. */
}

function autoRefreshLabel() {
	return dashboardAutoRefreshEnabled ? _('Auto Refresh: On') : _('Auto Refresh: Off');
}

function syncAutoRefreshIndicator() {
	var pollIndicator = document.getElementById('xhr_poll_status');
	var indicator = document.getElementById('airui_dashboard_auto_refresh');
	var header = document.querySelector('header');

	if (!header)
		return;

	if (pollIndicator)
		pollIndicator.style.setProperty('display', 'none', 'important');

	if (!dashboardHeaderObserver && window.MutationObserver) {
		dashboardHeaderObserver = new MutationObserver(function() {
			window.setTimeout(syncAutoRefreshIndicator, 0);
		});
		dashboardHeaderObserver.observe(header, {
			attributes: true,
			attributeFilter: [ 'style' ],
			childList: true,
			subtree: true
		});
	}

	if (!indicator) {
		indicator = document.createElement('button');
		indicator.id = 'airui_dashboard_auto_refresh';
		indicator.type = 'button';
		indicator.className = 'airui-auto-refresh-toggle';
		header.appendChild(indicator);
	}

	indicator.textContent = autoRefreshLabel();
	indicator.classList.toggle('is-off', !dashboardAutoRefreshEnabled);
	indicator.setAttribute('aria-pressed', dashboardAutoRefreshEnabled ? 'true' : 'false');
	indicator.setAttribute('title', _('Toggle automatic dashboard refresh'));
	indicator.onclick = function(event) {
		event.preventDefault();
		dashboardAutoRefreshEnabled = !dashboardAutoRefreshEnabled;
		try {
			window.localStorage.setItem(dashboardAutoRefreshStorageKey, dashboardAutoRefreshEnabled ? 'on' : 'off');
		}
		catch (e) {
			/* The setting remains active until this page is closed. */
		}
		syncAutoRefreshIndicator();
	};
}

function dashboardData() {
	if (!lastSerialNum)
		fetchSerialNum();
	if (!cachedVersionInfo)
		fetchVersionInfo();
	return callStatusSnapshot();
}

function validEnvelope(response) {
	return response && response.ok !== false && response.data;
}

function updatedLabel(isPreserved) {
	if (isPreserved)
		return _('Using cached data (refresh failed at %s)').format(new Date().toLocaleTimeString());
	return _('Updated at %s').format(new Date().toLocaleTimeString());
}

function resolveFast(promise, fallback) {
	return Promise.race([
		L.resolveDefault(promise, fallback),
		new Promise(function(resolve) {
			window.setTimeout(function() { resolve(fallback); }, 10000);
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
			if (map[currentMac].associated == null)
				map[currentMac].associated = false;
			map[currentMac].ifname = currentIface || map[currentMac].ifname || '';
			continue;
		}

		if (!currentMac)
			continue;

		if (/^flags=/.test(line) && line.indexOf('[ASSOC]') > -1 && line.indexOf('[AUTHORIZED]') > -1) {
			map[currentMac].associated = true;
			map[currentMac].ifname = currentIface || map[currentMac].ifname || '';
		}

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
	var stations = parseWirelessStations(payload.wireless_stations);

	return Object.keys(stations).filter(function(mac) {
		return stations[mac].associated !== false;
	}).length;
}

function topClients(payload, leases) {
	var rows = [];
	var seen = {};
	var runtime = payload.wireless && payload.wireless.runtime || {};
	var leasesByKey = leaseMap(leases);
	var stationDump = parseWirelessStations(payload.wireless_stations);
	var identities = payload.client_identities || {};
	var identitiesByMac = {};
	var ifaceMeta = {};

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
			var band = radio.config && radio.config.band == '2g' ? '2.4 GHz' :
				(radio.config && radio.config.band == '5g' ? '5 GHz' : radioName);
			ifaceMeta[iface.ifname] = { ssid: ssid, band: band };

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
					ipAddress: identity.ipAddress || lease.ip || sta.ip || '-',
					ssid: ssid,
					band: band,
					signal: signal != null ? '%d dBm'.format(signal) : '-',
					traffic: fmtBytes(bytes),
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
		var meta = ifaceMeta[dump.ifname] || {};

		if (dump.associated === false)
			return;

		add({
			mac: mac,
			ip: identity.ipAddress || lease.ip || '',
			name: identity.hostname || lease.host || _('Unknown client'),
			ipAddress: identity.ipAddress || lease.ip || '-',
			ssid: meta.ssid || dump.ifname || _('Wi-Fi'),
			band: meta.band || '-',
			signal: dump.signal != null ? '%d dBm'.format(dump.signal) : '-',
			traffic: fmtBytes(bytes),
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
	return E('div', { 'class': 'card kpi', 'role': 'group', 'aria-label': label }, [
		active ? E('span', { 'class': 'air-status-pill is-positive kpi-status' }, _('Active')) : '',
		E('div', { 'class': 'label' }, label),
		E('div', { 'class': 'value' }, value || '-'),
		E('div', { 'class': 'sub' }, subtext || '')
	]);
}

function modeKpi(label, value, statusText, actionContent, pillText, pillClass) {
	var actionNodes = [
		E('span', { 'style': 'color:#8c8c8c;font-weight:600;' }, _('Action Required: '))
	];
	if (Array.isArray(actionContent)) {
		for (var i = 0; i < actionContent.length; i++)
			actionNodes.push(actionContent[i]);
	} else if (actionContent != null) {
		actionNodes.push(actionContent);
	}

	return E('div', { 'class': 'card kpi', 'role': 'group', 'aria-label': label }, [
		pillText ? E('span', { 'class': 'air-status-pill ' + (pillClass || 'is-positive') + ' kpi-status' }, pillText) : '',
		E('div', { 'class': 'label' }, label),
		E('div', { 'class': 'value' }, value || '-'),
		E('div', { 'class': 'sub', 'style': 'display:flex;flex-direction:column;gap:5px;font-size:11px;line-height:1.4;margin-top:auto;width:100%;text-align:left;' }, [
			E('div', { 'style': 'color:#333;' }, [
				E('span', { 'style': 'color:#8c8c8c;font-weight:600;' }, _('Status: ')),
				statusText
			]),
			E('div', { 'style': 'color:#333;' }, actionNodes)
		])
	]);
}

function statusFooter() {
	return E('footer', { 'class': 'status-page-footer' }, _('© AirPro Technology India Ltd. All rights reserved.'));
}

function formatLinkSpeed(speed) {
	speed = Number(speed) || 0;

	if (speed >= 1000) {
		var gbps = speed / 1000;
		return _('%s Gbps').format(gbps % 1 ? gbps.toFixed(1) : gbps.toFixed(0));
	}

	return speed > 0 ? _('%d Mbps').format(speed) : _('Unavailable');
}

function uplinkSummary(payload) {
	var link = payload.uplink || {};
	var ifaces = payload.interfaces || {};
	var uplink = ifaces.wan && ifaces.wan.available !== false ? ifaces.wan : ifaces.lan || {};
	var available = link.available === true;
	var up = available ? link.carrier === true :
		(Object.keys(uplink).length > 0 && uplink.available !== false && uplink.up === true);
	var speed = formatLinkSpeed(link.speed_mbps);
	var duplex = link.duplex ? _('%s Duplex').format(link.duplex) : '';
	var value = up ? (link.speed_mbps ? [ speed, duplex ].filter(Boolean).join(' / ') : _('Up')) : _('Down');

	return {
		up: up,
		value: value,
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
		return E('div', {
			'class': 'card detail-card top-clients-card',
			'role': 'region',
			'aria-label': _('Top 5 Clients')
		}, children);
	}

	children.push(E('div', { 'class': 'top-client-grid top-client-labels', 'role': 'row' }, [
		E('span', { 'role': 'columnheader' }, _('Client')),
		E('span', { 'role': 'columnheader' }, _('IP Address')),
		E('span', { 'role': 'columnheader' }, _('SSID / Band')),
		E('span', { 'role': 'columnheader' }, _('Signal')),
		E('span', { 'role': 'columnheader' }, _('Traffic (Rx + Tx)'))
	]));

	for (var i = 0; i < rows.length; i++) {
		children.push(E('div', { 'class': 'top-client-grid top-client-row', 'role': 'row' }, [
			E('span', { 'class': 'top-client-identity', 'role': 'cell' }, [
				E('strong', {}, rows[i].name),
				E('small', {}, rows[i].mac)
			]),
			E('strong', { 'role': 'cell' }, rows[i].ipAddress),
			E('span', { 'class': 'top-client-network', 'role': 'cell' }, [
				E('strong', {}, rows[i].ssid),
				E('small', {}, rows[i].band)
			]),
			E('strong', { 'role': 'cell' }, rows[i].signal),
			E('strong', { 'role': 'cell' }, rows[i].traffic)
		]));
	}

	return E('div', {
		'class': 'card detail-card top-clients-card',
		'role': 'table',
		'aria-label': _('Top 5 Clients')
	}, children);
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
		var live = validEnvelope(data);
		var isPreserved = false;

		if (live) {
			lastValidDashboardEnvelope = data;
		} else if (lastValidDashboardEnvelope) {
			data = lastValidDashboardEnvelope;
			live = true;
			isPreserved = true;
		}

		var payload = envelopeData(data);
		var clientsPayload = payload;
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
		var model = (cachedVersionInfo && cachedVersionInfo.model) || 'AirPro AP520';
		var target = (cachedVersionInfo && cachedVersionInfo.platform) || 'airos';
		var version = (cachedVersionInfo && cachedVersionInfo.version) || '1.2';
		var load = info.load && info.load.length ? (info.load[0] / 65536).toFixed(2) : '0.00';
		var currentMode = payload.mode && payload.mode.current || _('Standalone');
		var isCloud = String(currentMode).toLowerCase().indexOf('cloud') > -1;
		var isOnline = payload.mode && (payload.mode.online === true || payload.mode.online === 1 || payload.mode.online === '1');
		var devId = payload.mode && payload.mode.device_id || '';
		var isRegistered = payload.mode && (payload.mode.registered === true || payload.mode.registered === 1 || payload.mode.controller_state === 'registered' || (devId && devId !== 'XXXXXXXXXX' && devId.length === 10));
		var netValues = uciValues(payload.network || {}, 'uci') || (payload.network && payload.network.values) || {};
		var lanNet = netValues.lan || {};
		var lanIface = payload.interfaces && payload.interfaces.lan || {};
		var lanIp = lanIface.ipaddr || (lanIface['ipv4-address'] && lanIface['ipv4-address'][0] && lanIface['ipv4-address'][0].address) || lanNet.ipaddr || '';
		var isFallback = (lanIp === '192.168.188.253') || (lanNet.in_fallback === '1' || lanNet.in_fallback === 1);
		var lanProto = lanNet.proto || lanIface.proto || '';
		var isDhcpPending = (lanProto === 'dhcp') && (!lanIp || lanIp === '0.0.0.0') && !isFallback;

		var modePillText = _('Active');
		var modePillClass = 'is-positive';
		var modeStatusText = '';
		var modeActionContent = '';

		var visibleState = payload.mode && payload.mode.visible_state || '';
		var cloudDowntime = payload.mode && payload.mode.cloud_down_duration_sec || 0;

		if (isCloud) {
			if (isFallback) {
				modePillText = _('Fallback Active');
				modePillClass = 'is-warning';
				modeStatusText = _('Recovery IP 192.168.188.253 Active');
				modeActionContent = [
					_('Configure static IP or a '),
					E('a', {
						'href': L.url('admin/maintenance/system_maintenance') + '#maintenance-reboot',
						'style': 'color:#0066cc;text-decoration:underline;font-weight:600;display:inline;'
					}, _('reboot'))
				];
			} else if (isDhcpPending) {
				modePillText = _('DHCP Pending');
				modePillClass = 'is-warning';
				modeStatusText = _('Acquiring IP via DHCP (waiting up to 3 min)');
				modeActionContent = _('Connect uplink cable to live DHCP network or await fallback IP');
			} else if (isOnline) {
				modePillText = _('Online');
				modePillClass = 'is-positive';
				modeStatusText = _('Connected to Cloud Controller');
				modeActionContent = _('None (Cloud synchronised)');
			} else if (visibleState === 'OPERATIONAL_DEGRADED') {
				modePillText = _('Operational (Cloud Offline)');
				modePillClass = 'is-warning';
				modeStatusText = cloudDowntime > 0 ?
					_('Local AP Active - Cloud Offline (%ds)').format(cloudDowntime) :
					_('Local AP Active - Cloud Offline');
				modeActionContent = _('Local Wi-Fi and routing operational. Check WAN uplink / cloud reachability.');
			} else if (!isRegistered) {
				modePillText = _('Unclaimed');
				modePillClass = 'is-warning';
				modeStatusText = _('Awaiting Cloud Enrollment');
				modeActionContent = _('Claim device on Cloud Controller using Serial / MAC');
			} else {
				modePillText = _('Disconnected');
				modePillClass = 'is-danger';
				modeStatusText = _('Cloud Controller Unreachable');
				modeActionContent = _('Check internet uplink / firewall port 35930');
			}
		} else {
			var hasCustomSsid = false;
			for (var r = 0; r < radios.length; r++) {
				var s = (radios[r].ssid || '');
				if (s && s !== 'Airpro' && s.indexOf('Airpro_') !== 0 && s.indexOf('Airpro2g') !== 0 && s.indexOf('Airpro5g') !== 0) {
					hasCustomSsid = true;
					break;
				}
			}

			if (hasCustomSsid) {
				modePillText = _('Active');
				modePillClass = 'is-positive';
				modeStatusText = _('Local AP Mode Operational');
				modeActionContent = _('None (Operating normally)');
			} else {
				modePillText = _('Unconfigured');
				modePillClass = 'is-neutral';
				modeStatusText = _('Running Factory Default Wi-Fi');
				modeActionContent = [
					_('Configure wireless SSIDs and passwords in '),
					E('a', {
						'href': L.url('admin/network/wireless'),
						'style': 'color:#0066cc;text-decoration:underline;font-weight:600;'
					}, _('Network settings'))
				];
			}
		}

		var page;
		var refresh = function() {
			if (document.hidden)
				return Promise.resolve();

			var generation = ++dashboardGeneration;
			var currentPage = document.querySelector('#maincontent .airdash.status-page') || page;
			var button = currentPage && currentPage.querySelector('.status-page-refresh');
			var updated = currentPage && currentPage.querySelector('.status-page-updated');

			if (button) {
				button.disabled = true;
				button.setAttribute('aria-busy', 'true');
			}
			if (updated) {
				updated.classList.remove('is-stale');
				updated.classList.add('is-loading');
				updated.textContent = _('Refreshing live data...');
			}

			return resolveFast(dashboardData(), {
				ok: false,
				error: { message: 'Dashboard request timed out' }
			}).then(function(result) {
				if (generation != dashboardGeneration)
					return;
				if (!validEnvelope(result)) {
					if (lastValidDashboardEnvelope) {
						if (updated) {
							updated.classList.remove('is-loading');
							updated.classList.add('is-stale');
							updated.textContent = _('Refresh failed (%s). Retaining prior values.').format(
								result && result.error && result.error.message || 'error'
							);
						}
						return;
					}
					throw new Error(result && result.error && result.error.message || 'Invalid dashboard response');
				}

				var nextPage = buildDashboardPage(result);
				if (currentPage && currentPage.parentNode)
					currentPage.parentNode.replaceChild(nextPage, currentPage);
				page = nextPage;
			}).catch(function(error) {
				if (generation == dashboardGeneration && updated) {
					updated.classList.remove('is-loading');
					updated.classList.add('is-stale');
					updated.textContent = _('Update failed: %s (retaining prior values)').format(error && error.message ? error.message : String(error));
				}
				if (window.console && console.error)
					console.error('AirUI dashboard refresh failed', error);
			}).finally(function() {
				if (button && button.isConnected) {
					button.disabled = false;
					button.removeAttribute('aria-busy');
				}
			});
		};

		page = E('div', { 'class': 'airdash status-page' }, [
			E('section', { 'class': 'status-page-hero' }, [
				E('div', { 'class': 'status-page-copy' }, [
					E('h1', {}, _('Dashboard'))
				]),
				E('div', { 'class': 'status-page-actions' }, [
					E('button', { 'class': 'status-page-refresh', 'type': 'button', 'click': refresh }, _('Refresh')),
					E('small', { 'class': (live && !isPreserved) ? 'status-page-updated' : 'status-page-updated is-stale' },
						live ? updatedLabel(isPreserved) : _('Live data unavailable'))
				])
			]),
			isPreserved ? E('div', {
				'class': 'airui-data-state is-stale',
				'role': 'alert'
			}, _('The dashboard refresh timed out or failed. Displaying previously captured telemetry.')) : (live ? '' : E('div', {
				'class': 'airui-data-state is-stale',
				'role': 'alert'
			}, _('The dashboard could not load live data. Values are unavailable until a refresh succeeds.'))),
			live ? E('section', { 'class': 'kpis' }, [
				kpi(_('Uplink'), uplink.value, uplink.subtext, uplink.up),
				kpi(_('Clients'), String(clients), _('Wi-Fi associated'), clients > 0),
				kpi(_('Wireless Interfaces'), _('%d active of %d').format(activeRadios, radios.length || 0), _('Configured wireless interfaces'), activeRadios > 0),
				kpi(_('Uptime'), fmtUptime(info.uptime), _('Since last boot'), false),
				modeKpi(_('Current Mode'), currentMode, modeStatusText, modeActionContent, modePillText, modePillClass)
			]) : '',
			live ? E('section', { 'class': 'metrics' }, [
				donutCard('airdash-cpu', _('CPU Utilisation'), cpuPct, _('Load: %s').format(load), [
					[ _('Used'), '%d%%'.format(cpuPct), 'bullet' ],
					[ _('Idle'), '%d%%'.format(100 - cpuPct), 'bullet light' ]
				], false),
				donutCard('airdash-memory', _('Memory Utilisation'), memPct, _('Total: %s').format(fmtBytes(total)), [
					[ _('Used'), fmtBytes(used), 'bullet navy' ],
					[ _('Free'), fmtBytes(free), 'bullet light' ]
				], true)
			]) : '',
			live ? E('section', { 'class': 'details' }, [
				detailCard(_('System Details'), [
					[ _('Firmware'), version ],
					[ _('Serial Number'), lastSerialNum || (payload.mode && payload.mode.serial_num) || '-' ],
					[ _('Current Mode'), currentMode ],
					[ _('Model Name'), model ]
				]),
				detailCard(_('Storage Devices'), [
					[ _('USB Interface'), _('None'), 'v muted' ],
					[ _('Disk Partition'), _('Not mounted'), 'v muted' ],
					[ _('Health'), _('Ready'), 'v good' ],
					[ _('Status'), _('No connected devices') ]
				])
			]) : '',
			live ? E('section', { 'class': 'details dashboard-bottom' }, [
				topClientsCard(clientRows)
			]) : '',
			statusFooter()
		]);

		window.setTimeout(syncAutoRefreshIndicator, 0);

		if (!dashboardPollRegistered) {
			dashboardPollRegistered = true;
			poll.add(function() {
				return dashboardAutoRefreshEnabled ? refresh() : Promise.resolve();
			}, 60);
		}

		return page;
	}

var dashboardView = view.extend({
	load: function() {
		dashboardGeneration++;
		dashboardPollRegistered = false;
		return Promise.all([
			resolveFast(callStatusSnapshot(), {
				ok: false,
				error: { message: 'Dashboard request timed out' }
			}),
			fetchSerialNum(),
			fetchVersionInfo()
		]).then(function(results) {
			return results[0];
		});
	},

	render: buildDashboardPage,

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

return dashboardView;
