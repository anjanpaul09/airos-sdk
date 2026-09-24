'use strict';
'require view';
'require rpc';
'require ui';

var callStatusClients = rpc.declare({ object: 'airui.status', method: 'clients', expect: { '': {} } });
var callClientDisconnect = rpc.declare({ object: 'airui.status', method: 'client_disconnect', params: [ 'macaddr' ], expect: { '': {} } });

function text(value, fallback) {
	if (value === null || value === undefined || value === '')
		return fallback || '-';

	return String(value);
}

function envelopeData(response) {
	return response && response.ok !== false && response.data ? response.data : {};
}

function uciValues(payload, config) {
	var root = payload && payload[config || 'uci'] || {};
	return root.values || root;
}

function wirelessSectionMap(payload) {
	var values = uciValues(payload.wireless || {}, 'uci');
	var map = {};

	Object.keys(values || {}).forEach(function(name) {
		var row = values[name] || {};

		if (row['.type'] == 'wifi-iface' || row.type == 'wifi-iface' || row.device) {
			row.section = row.section || name;
			map[name] = row;
		}
	});

	return map;
}

function networkDeviceMap(payload) {
	var values = payload && payload.network && payload.network.values || {};
	var map = {};

	Object.keys(values || {}).forEach(function(name) {
		var row = values[name] || {};
		var device = row.device || row.name;

		if (row['.type'] == 'interface' && device)
			map[device] = name;

		if (row['.type'] == 'device' && row.name && row.name.indexOf('br-') == 0) {
			var bridgeNetwork = row.name.replace(/^br-/, '');

			if (values[bridgeNetwork])
				map[row.name] = bridgeNetwork;
		}
	});

	return map;
}

function wirelessNetworkMap(payload) {
	var sections = wirelessSectionMap(payload);
	var devices = networkDeviceMap(payload);
	var map = {};

	Object.keys(sections || {}).forEach(function(name) {
		var row = sections[name] || {};
		var networks = Array.isArray(row.network) ? row.network : [ row.network ];
		var ssid = row.ssid || name;

		for (var i = 0; i < networks.length; i++) {
			var network = networks[i];

			if (!network)
				continue;

			map[network] = ssid;

			Object.keys(devices).forEach(function(device) {
				if (devices[device] == network)
					map[device] = ssid;
			});
		}
	});

	return map;
}

function fmtDuration(seconds) {
	seconds = Math.max(0, Math.floor(seconds || 0));

	var days = Math.floor(seconds / 86400);
	var hours = Math.floor((seconds % 86400) / 3600);
	var mins = Math.floor((seconds % 3600) / 60);

	if (days)
		return '%dd %dh'.format(days, hours);

	if (hours)
		return '%dh %dm'.format(hours, mins);

	if (mins)
		return '%dm'.format(mins);

	return _('Connected now');
}

function leaseMap(data) {
	var map = {};
	var leases = Array.isArray(data.dhcp_leases) ? data.dhcp_leases : [];
	var leases6 = Array.isArray(data.dhcp6_leases) ? data.dhcp6_leases : [];

	for (var i = 0; i < leases.length; i++) {
		var ip = leases[i].ipaddr || leases[i].ip;
		var mac = (leases[i].macaddr || leases[i].mac || '').toUpperCase();

		if (ip)
			map[ip] = {
				ip: ip,
				mac: mac || '-',
				host: leases[i].hostname || leases[i].host || '-'
			};

		if (mac)
			map[mac] = map[ip];
	}

	for (var j = 0; j < leases6.length; j++) {
		var ip6 = leases6[j].ip6addr || leases6[j].ip;
		var mac6 = (leases6[j].macaddr || leases6[j].mac || '').toUpperCase();

		if (ip6)
			map[ip6] = {
				ip: ip6,
				mac: mac6 || '-',
				host: leases6[j].hostname || leases6[j].host || '-'
			};

		if (mac6 && !map[mac6])
			map[mac6] = map[ip6];
	}

	return map;
}

function parseNeigh(text, leases) {
	var rows = [];
	var seen = {};
	var lines = (text || '').trim().split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var m = lines[i].match(/^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-f:]{17}))?.*\s+(\S+)$/i);

		if (!m || m[4] == 'FAILED')
			continue;

		var ip = m[1];
		var iface = m[2];
		var mac = (m[3] || '').toUpperCase();
		var key = ip + mac + iface;
		var lease = leases[ip] || leases[mac] || {};

		if (seen[key])
			continue;

		seen[key] = true;
		rows.push({
			host: lease.host || '-',
			ip: ip,
			mac: mac || lease.mac || '-',
			iface: iface,
			type: iface == 'br-lan' || iface.indexOf('eth') == 0 ? _('Wired') : _('Network'),
			link: '-',
			state: m[4],
			fromLease: !!(lease.ip || lease.host || lease.mac)
		});
	}

	return rows;
}

function collectLeaseClients(data, rows) {
	var out = [];
	var seen = {};
	var leases = Array.isArray(data && data.dhcp_leases) ? data.dhcp_leases : [];
	var leases6 = Array.isArray(data && data.dhcp6_leases) ? data.dhcp6_leases : [];

	function keyFor(row) {
		return text(row && row.mac, '').toUpperCase() || text(row && row.ip, '');
	}

	function remember(row) {
		var key = keyFor(row);

		if (key && key != '-')
			seen[key] = true;
	}

	function addLease(lease, family) {
		var ip = lease.ipaddr || lease.ip6addr || lease.ip;
		var mac = (lease.macaddr || lease.mac || '').toUpperCase();
		var key = mac || ip;

		if (!key || seen[key])
			return;

		seen[key] = true;
		out.push({
			host: lease.hostname || lease.host || '-',
			ip: ip || '-',
			mac: mac || '-',
			iface: family == 6 ? _('DHCPv6 lease') : _('DHCP lease'),
			type: _('Network'),
			link: '-',
			state: _('Known')
		});
	}

	for (var i = 0; i < (rows || []).length; i++)
		remember(rows[i]);

	for (var j = 0; j < leases.length; j++)
		addLease(leases[j] || {}, 4);

	for (var k = 0; k < leases6.length; k++)
		addLease(leases6[k] || {}, 6);

	return out;
}

function directLanInterfaces(payload) {
	var values = payload && payload.network && payload.network.values || {};
	var interfaces = { lan: true };

	Object.keys(values).forEach(function(name) {
		var row = values[name] || {};
		var ports = Array.isArray(row.ports) ? row.ports : [ row.ports ];

		if (row['.type'] == 'device' && ports.indexOf('lan') > -1)
			interfaces[row.name || name] = true;
	});

	return interfaces;
}

function isKnownNetworkClient(client, lanInterfaces) {
	var iface = text(client && client.iface, '').toLowerCase();
	var mac = text(client && client.mac, '');

	if (!iface || mac == '-')
		return false;

	return !!lanInterfaces[iface];
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
	var lines = (text || '').split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		var prefix = line.match(/^interface\s+(\S+)\s+(.*)$/);

		if (!prefix)
			continue;

		currentIface = prefix[1];
		line = prefix[2];

		var station = line.match(/^Station\s+([0-9a-f:]{17})/i);
		var hostapdStation = line.match(/^([0-9a-f:]{17})$/i);
		if (station || hostapdStation) {
			currentMac = (station ? station[1] : hostapdStation[1]).toUpperCase();
			map[currentMac] = map[currentMac] || {};
			map[currentMac].ifname = currentIface;
			continue;
		}

		if (!currentMac)
			continue;

		if (/^\s*flags=/.test(line))
			map[currentMac].associated = line.indexOf('[ASSOC]') > -1 && line.indexOf('[AUTHORIZED]') > -1;

		var signal = line.match(/^\s*signal:\s*(-?\d+)/);
		var connected = line.match(/^\s*connected time:\s*(\d+)/);
		var hostapdSignal = line.match(/^\s*signal=(-?\d+)/);
		var hostapdConnected = line.match(/^\s*connected_time=(\d+)/);

		if (signal)
			map[currentMac].signal = +signal[1];
		if (hostapdSignal)
			map[currentMac].signal = +hostapdSignal[1];
		if (connected)
			map[currentMac].connected_time = +connected[1];
		if (hostapdConnected)
			map[currentMac].connected_time = +hostapdConnected[1];
	}

	return map;
}

function collectWifiClients(payload, leases) {
	var rows = [];
	var seen = {};
	var ifaceNames = {};
	var runtime = payload.wireless && payload.wireless.runtime || {};
	var sections = wirelessSectionMap(payload);
	var stationDump = parseWirelessStations(payload.wireless_stations);

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var sectionName = iface.section || iface.config && iface.config['.name'];
			var section = sections[sectionName] || iface.config || {};
			var ssid = section.ssid || iface.ssid || iface.ifname || sectionName || '-';
			var ifname = iface.ifname || sectionName || '-';
			var stations = stationList(iface.stations || iface.assoclist || iface.associations);
			ifaceNames[ifname] = ssid;

			for (var j = 0; j < stations.length; j++) {
				var sta = stations[j] || {};
				var mac = (sta.mac || sta.macaddr || '').toUpperCase();
				var lease = leases[mac] || {};
				var dump = stationDump[mac] || {};
				var signal = sta.signal != null ? sta.signal : (sta.rssi != null ? sta.rssi : dump.signal);
				var connected = sta.connected_time != null ? sta.connected_time : dump.connected_time;
				var link = signal != null ? '%d dBm'.format(signal) : '-';

				if (!mac || seen[mac])
					continue;

				seen[mac] = true;
				rows.push({
					host: lease.host || sta.hostname || '-',
					ip: lease.ip || sta.ip || '-',
					mac: mac,
					iface: ssid,
					type: _('Wireless'),
					link: link,
					rssi: link,
					duration: connected ? fmtDuration(connected) : _('Connected now'),
					linkType: sta.mlo ? 'MLO' : 'Non-MLO',
					state: _('Associated'),
					ifname: ifname
				});
			}
		}
	});

	Object.keys(stationDump).forEach(function(mac) {
		var sta = stationDump[mac] || {};
		var lease = leases[mac] || {};

		if (seen[mac] || sta.associated === false)
			return;

		seen[mac] = true;
		rows.push({
			host: lease.host || '-',
			ip: lease.ip || '-',
			mac: mac,
			iface: ifaceNames[sta.ifname] || sta.ifname || '-',
			type: _('Wireless'),
			link: sta.signal != null ? '%d dBm'.format(sta.signal) : '-',
			rssi: sta.signal != null ? '%d dBm'.format(sta.signal) : '-',
			duration: sta.connected_time ? fmtDuration(sta.connected_time) : _('Connected now'),
			linkType: _('Wi-Fi'),
			state: _('Associated'),
			ifname: sta.ifname || '-'
		});
	});

	return rows;
}

function inferWifiClients(rows, wifiMap, seenWireless, stationDump) {
	var inferred = [];
	var networkRows = [];

	for (var i = 0; i < rows.length; i++) {
		var client = rows[i] || {};
		var ssid = wifiMap[client.iface];
		var mac = (client.mac || '').toUpperCase();
		var dump = stationDump && stationDump[mac] || {};
		var signal = dump.signal != null ? '%d dBm'.format(dump.signal) : '-';

		if (!ssid || seenWireless[mac]) {
			networkRows.push(client);
			continue;
		}

		seenWireless[mac] = true;
		inferred.push({
			host: client.host || '-',
			ip: client.ip || '-',
			mac: client.mac || '-',
			iface: ssid,
			type: _('Wireless'),
			link: '-',
			rssi: signal,
			duration: dump.connected_time ? fmtDuration(dump.connected_time) : '-',
			linkType: _('Wi-Fi'),
			state: client.state || _('Known'),
			ifname: client.iface || '-'
		});
	}

	return {
		wifi: inferred,
		network: networkRows
	};
}

function enrichClientIdentities(rows, identities) {
	var byMac = {};

	Object.keys(identities || {}).forEach(function(mac) {
		byMac[mac.toUpperCase()] = identities[mac] || {};
	});

	for (var i = 0; i < rows.length; i++) {
		var identity = byMac[text(rows[i].mac, '').toUpperCase()] || {};

		if (identity.found === false)
			continue;

		rows[i].host = identity.hostname || rows[i].host;
		rows[i].ip = identity.ipAddress || identity.ipaddr || rows[i].ip;
		rows[i].osInfo = identity.osInfo || identity.os || '-';
	}

	return rows;
}

function stat(label, value, subtext, active) {
	return E('article', { 'class': active ? 'client-stat is-active' : 'client-stat' }, [
		E('span', { 'class': 'client-stat-dot' }),
		E('small', {}, label),
		E('strong', { 'class': 'tech' }, text(value)),
		E('em', {}, subtext || '')
	]);
}

function row(client) {
	return E('div', { 'class': 'client-row' }, [
		E('div', { 'class': 'client-main' }, [
			E('strong', {}, text(client.host, _('Unknown device'))),
			E('span', {}, [
				E('b', { 'class': 'tech' }, text(client.ip)),
				' / ',
				E('b', { 'class': 'tech' }, text(client.mac))
			])
		]),
		E('span', { 'class': 'client-chip' }, client.type),
		E('span', { 'class': 'tech' }, text(client.iface)),
		E('span', {}, text(client.link)),
		E('span', { 'class': client.state == 'REACHABLE' || client.state == 'STALE' || client.state == _('Associated') ? 'client-state is-on' : 'client-state' }, text(client.state))
	]);
}

function disconnectButton(client) {
	return E('button', {
		'class': 'client-disconnect',
		'type': 'button',
		'title': _('Disconnect client'),
		'click': function(ev) {
			var button = ev.currentTarget;
			button.disabled = true;

			return callClientDisconnect(client.mac).then(function(response) {
				if (!response || response.ok === false)
					throw new Error(response && response.errors && response.errors[0] && response.errors[0].message || _('Disconnect failed'));

				var seconds = response.data && response.data.reconnect_block_seconds || 60;
				ui.addNotification(null, E('p', {}, _('%s was disconnected. Reconnection is paused for %d seconds.').format(text(client.host, client.mac), seconds)), 'info');
				window.setTimeout(function() { window.location.reload(); }, 1500);
			}).catch(function(error) {
				button.disabled = false;
				ui.addNotification(null, E('p', {}, error.message || _('Disconnect failed')), 'error');
			});
		}
	}, _('Disconnect'));
}

function wifiRow(client) {
	return E('div', { 'class': 'client-row wifi-client-row' }, [
		E('span', { 'class': 'tech' }, text(client.ip)),
		E('span', { 'class': 'tech' }, text(client.mac)),
		E('div', { 'class': 'client-main' }, [
			E('strong', {}, text(client.host, _('Unknown device')))
		]),
		E('span', {}, text(client.osInfo)),
		E('span', { 'class': 'tech' }, text(client.iface)),
		E('span', { 'class': 'tech' }, text(client.duration)),
		E('span', { 'class': 'tech' }, text(client.rssi)),
		E('span', { 'class': client.linkType == 'MLO' ? 'client-chip is-mlo' : 'client-chip' }, text(client.linkType)),
		disconnectButton(client)
	]);
}

function table(title, rows, emptyText) {
	return E('section', { 'class': 'client-panel' }, [
		E('div', { 'class': 'client-panel-head' }, [
			E('h2', {}, title),
			E('span', { 'class': 'tech' }, String(rows.length))
		]),
		E('div', { 'class': 'client-table' }, [
			E('div', { 'class': 'client-head' }, [
				E('span', {}, _('Client')),
				E('span', {}, _('Type')),
				E('span', {}, _('Interface')),
				E('span', {}, _('Link')),
				E('span', {}, _('State'))
			]),
			rows.length ? E('div', { 'class': 'client-body' }, rows.map(row)) :
				E('div', { 'class': 'client-empty' }, emptyText)
		])
	]);
}

function wifiTable(title, rows, emptyText) {
	return E('section', { 'class': 'client-panel wifi-client-panel' }, [
		E('div', { 'class': 'client-panel-head' }, [
			E('h2', {}, title),
			E('span', { 'class': 'tech' }, String(rows.length))
		]),
		E('div', { 'class': 'client-table' }, [
			E('div', { 'class': 'client-head wifi-client-head' }, [
				E('span', {}, _('IP')),
				E('span', {}, _('MAC')),
				E('span', {}, _('Hostname')),
				E('span', {}, _('OS')),
				E('span', {}, _('Interface')),
				E('span', {}, _('Duration')),
				E('span', {}, _('RSSI')),
				E('span', {}, _('Link Type')),
				E('span', {}, _('Disconnect'))
			]),
			rows.length ? E('div', { 'class': 'client-body' }, rows.map(wifiRow)) :
				E('div', { 'class': 'client-empty' }, emptyText)
		])
	]);
}

return view.extend({
	load: function() {
		return L.resolveDefault(callStatusClients(), {});
	},

	render: function(data) {
		var payload = envelopeData(data);
		var leases = leaseMap(payload.leases || {});
		var lanRows = parseNeigh((payload.neigh4 || '') + '\n' + (payload.neigh6 || ''), leases);
		var wifiRows = collectWifiClients(payload, leases);
		var lanInterfaces = directLanInterfaces(payload);
		var seenWireless = {};

		for (var i = 0; i < wifiRows.length; i++)
			seenWireless[(wifiRows[i].mac || '').toUpperCase()] = true;

		lanRows = lanRows.filter(function(client) {
			return isKnownNetworkClient(client, lanInterfaces) && !seenWireless[(client.mac || '').toUpperCase()];
		});

		wifiRows = enrichClientIdentities(wifiRows, payload.client_identities);
		lanRows = lanRows.filter(function(client) {
			return !seenWireless[(client.mac || '').toUpperCase()];
		});

		var total = lanRows.length + wifiRows.length;

		return E('div', { 'class': 'airdash clients-page status-page' }, [
			E('section', { 'class': 'clients-hero status-page-hero' }, [
				E('div', {}, [
					E('span', { 'class': 'eyebrow' }, _('Clients')),
					E('h1', {}, _('Connected Clients')),
					E('p', {}, _('Live wireless and directly connected wired clients discovered from radio association, DHCP, and neighbor data.'))
				]),
				E('div', { 'class': 'status-page-actions' }, [
					E('button', {
						'class': 'clients-refresh status-page-refresh',
						'type': 'button',
						'click': function() { window.location.reload(); }
					}, _('Refresh')),
					E('small', {}, _('Updated just now'))
				])
			]),
			E('section', { 'class': 'client-stats' }, [
				stat(_('Total'), total, _('known clients'), total > 0),
				stat(_('Wireless Clients'), wifiRows.length, _('currently connected'), wifiRows.length > 0),
				stat(_('Wired Clients'), lanRows.length, _('directly connected to LAN'), lanRows.length > 0)
			]),
			wifiTable(_('Wireless Clients'), wifiRows, _('No wireless clients are currently connected.')),
			table(_('Wired Clients'), lanRows, _('No wired clients are currently connected.')),
			E('footer', { 'class': 'status-page-footer' }, _('© AirPro Technology India Ltd. All rights reserved.'))
			]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
