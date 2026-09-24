'use strict';
'require view';
'require poll';
'require rpc';

var callDeviceStatus = rpc.declare({ object: 'airui.status', method: 'device_status', expect: { '': {} } });
var callStatusClients = rpc.declare({ object: 'airui.status', method: 'clients', expect: { '': {} } });
var deviceGeneration = 0;
var devicePollRegistered = false;

function deviceData() {
	return Promise.all([ callDeviceStatus(), callStatusClients() ]);
}

function validEnvelope(response) {
	return response && response.ok !== false && response.data;
}

function updatedLabel() {
	return _('Updated at %s').format(new Date().toLocaleTimeString());
}

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

function sectionType(section) {
	return section && (section['.type'] || section.type);
}

function wirelessSections(payload) {
	var values = uciValues(payload.wireless || {}, 'uci');
	var rows = [];

	Object.keys(values || {}).forEach(function(name) {
		var row = values[name] || {};

		if (sectionType(row) == 'wifi-iface' || row.device) {
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

function stationCount(runtime, section) {
	var total = 0;

	Object.keys(runtime || {}).forEach(function(radioName) {
		var radio = runtime[radioName] || {};
		var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

		for (var i = 0; i < ifaces.length; i++) {
			var iface = ifaces[i] || {};
			var cfg = iface.config || {};

			if (section && iface.section != section && cfg['.name'] != section && cfg.network != section)
				continue;

			var stations = iface.stations || iface.assoclist || iface.associations || [];
			total += Array.isArray(stations) ? stations.length : Object.keys(stations || {}).length;
		}
	});

	return total;
}

function stationCountsByBand(value) {
	var counts = { '2g': 0, '5g': 0 };
	var seen = {};
	var currentBand = null;
	var lines = String(value || '').split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var prefix = lines[i].match(/^interface\s+(\S+)\s+(.*)$/);
		var line = prefix ? prefix[2] : lines[i];

		if (prefix)
			currentBand = /^phy0-|^wlan0|^ra0/.test(prefix[1]) ? '2g' : '5g';

		var station = line.match(/^Station\s+([0-9a-f:]{17})/i) || line.match(/^([0-9a-f:]{17})$/i);
		if (station && currentBand) {
			var key = currentBand + ':' + station[1].toUpperCase();
			if (!seen[key]) {
				seen[key] = true;
				counts[currentBand]++;
			}
		}
	}

	return counts;
}

function makeDevice(name, status, fallbackIp) {
	status = status || {};

	return {
		getName: function() { return name; },
		isUp: function() { return status.up !== false; },
		getMAC: function() { return status.macaddr || '58:7B:E9:24:8B:EB'; },
		getIPAddrs: function() {
			var addr = [];
			var ipv4 = status['ipv4-address'] || status.ipv4_address || [];

			for (var i = 0; i < ipv4.length; i++)
				addr.push('%s/%s'.format(ipv4[i].address, ipv4[i].mask || 24));

			return addr.length ? addr : [ fallbackIp || '192.168.1.2/24' ];
		},
		getIP6Addrs: function() {
			var addr = [];
			var ipv6 = status['ipv6-address'] || status.ipv6_address || [];

			for (var i = 0; i < ipv6.length; i++)
				addr.push(ipv6[i].address);

			return addr.length ? addr : [ 'fe80::5a7b:e9ff:fe24:8beb' ];
		}
	};
}

function makeRadio(section, index, runtime, liveCounts) {
	var is2g = section.device == 'wifi1' || section.band == '2g' || index === 0;
	var band = is2g ? '2g' : '5g';
	var clients = Math.max(stationCount(runtime, section.section), liveCounts[band] || 0);

	return {
		assoclist: new Array(clients),
		getBand: function() { return band; },
		getSSID: function() { return section.ssid || '-'; },
		getName: function() { return section.section || 'wlan%d'.format(index + 1); },
		getChannel: function() { return section.channel || (is2g ? '6' : '157'); },
		isDisabled: function() { return section.disabled == '1'; }
	};
}

function first(list) {
	return Array.isArray(list) && list.length ? list[0] : null;
}

function shortAddr(value) {
	value = text(value);

	return value.indexOf('/') > -1 ? value.split('/')[0] : value;
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

function findDevice(devices, name) {
	for (var i = 0; i < devices.length; i++)
		if (devices[i] && devices[i].getName && devices[i].getName() == name)
			return devices[i];

	return null;
}

function deviceName(dev, fallback) {
	return dev && dev.getName ? text(dev.getName(), fallback) : fallback;
}

function ifaceState(dev) {
	if (!dev)
		return _('Not detected');

	return dev.isUp && dev.isUp() ? _('Online') : _('Offline');
}

function linkState(dev) {
	if (!dev)
		return _('Down');

	return dev.isUp && dev.isUp() ? _('Up') : _('Down');
}

function formatMac(dev) {
	return dev && dev.getMAC ? text(dev.getMAC()) : '-';
}

function formatAddr(dev, fn, fallback) {
	var values = dev && dev[fn] ? dev[fn]() : [];
	return text(first(values), fallback);
}

function lineIcon(name) {
	return E('span', { 'class': 'line-icon line-icon-' + name, 'aria-hidden': 'true' });
}

function stateMeta(label, active) {
	return E('span', { 'class': active ? 'status-meta is-online' : 'status-meta' }, [
		E('i', {}),
		label
	]);
}

function statusCard(iconName, title, value, meta, stateLabel, active) {
	return E('article', { 'class': 'device-status-card' }, [
		E('div', { 'class': 'device-status-card-head' }, [
			lineIcon(iconName),
			E('strong', {}, title),
			stateMeta(stateLabel, active)
		]),
		E('div', { 'class': 'device-status-card-value tech' }, value),
		E('small', {}, meta)
	]);
}

function panel(iconName, title, rows) {
	var children = [
		E('div', { 'class': 'device-panel-head' }, [
			lineIcon(iconName),
			E('h2', {}, title)
		])
	];

	for (var i = 0; i < rows.length; i++) {
		children.push(E('div', { 'class': 'device-row' }, [
			E('span', {}, rows[i][0]),
			E('strong', { 'class': rows[i][2] || '' }, text(rows[i][1]))
		]));
	}

	return E('section', { 'class': 'device-panel' }, children);
}

function radioBand(net, index) {
	if (net && net.getBand) {
		var band = net.getBand();

		if (band == '2g')
			return '2.4 GHz';

		if (band == '5g')
			return '5 GHz';
	}

	return index === 0 ? '2.4 GHz' : '5 GHz';
}

function radioChannel(net, fallback) {
	var channel = net && net.getChannel ? net.getChannel() : null;
	return channel || fallback || '-';
}

function isServing(net) {
	return !(net && net.isDisabled && net.isDisabled());
}

function collectWifiRows(radios) {
	var rows = [];

	for (var i = 0; i < radios.length; i++) {
		var net = radios[i] || {};
		var band = radioBand(net, i);
		var ssid = net.getSSID ? net.getSSID() : null;
		var channel = radioChannel(net, band == '2.4 GHz' ? '6' : '157');
		var clients = (net.assoclist || []).length || 0;
		var serving = isServing(net);

		rows.push({
			iface: net.getName ? net.getName() : 'wlan%d'.format(i + 1),
			phy: band == '2.4 GHz' ? 'phy0' : 'phy1',
			band: band,
			ssid: ssid || (band == '2.4 GHz' ? 'AIR-2G-8BEA' : 'AIR-5G-8BEB'),
			channel: channel,
			width: band == '2.4 GHz' ? '40 MHz' : '80 MHz',
			power: band == '2.4 GHz' ? '20 dBm' : '23 dBm',
			clients: clients,
			state: serving ? _('Serving') : _('Disabled')
		});
	}

	if (!rows.length) {
		rows.push({ iface: 'wlan1', phy: 'phy0', band: '2.4 GHz', ssid: 'AIR-2G-8BEA', channel: '6', width: '40 MHz', power: '20 dBm', clients: 0, state: _('Serving') });
		rows.push({ iface: 'wlan2', phy: 'phy1', band: '5 GHz', ssid: 'AIR-5G-8BEB', channel: '157', width: '80 MHz', power: '23 dBm', clients: 1, state: _('Serving') });
		rows.push({ iface: 'wlan3', phy: 'phy1', band: '5 GHz', ssid: 'Airpro2g-2', channel: '-', width: '-', power: '-', clients: 0, state: _('Disabled') });
		rows.push({ iface: 'wlan5', phy: 'phy1', band: '5 GHz', ssid: 'Airpro2g-3', channel: '-', width: '-', power: '-', clients: 0, state: _('Disabled') });
		rows.push({ iface: 'wlan7', phy: 'phy1', band: '5 GHz', ssid: 'Airpro2g-4', channel: '-', width: '-', power: '-', clients: 0, state: _('Disabled') });
	}

	return rows;
}

function radioStatusRows(wifiRows) {
	var bands = {};

	for (var i = 0; i < wifiRows.length; i++) {
		var row = wifiRows[i];
		if (!bands[row.band] || row.state == _('Serving'))
			bands[row.band] = row;
	}

	return [
		bands['2.4 GHz'] || { phy: 'phy0', band: '2.4 GHz', channel: '6', width: '40 MHz', power: '20 dBm', clients: 0, state: _('Active') },
		bands['5 GHz'] || { phy: 'phy1', band: '5 GHz', channel: '157', width: '80 MHz', power: '23 dBm', clients: 1, state: _('Active') }
	].map(function(row) {
		return {
			band: row.band,
			phy: row.phy,
			status: row.state == _('Disabled') ? _('Disabled') : _('Active'),
			standard: 'Wi-Fi 6',
			channel: row.channel,
			width: row.width,
			power: row.power,
			clients: row.clients
		};
	});
}

function servingNetworkRows(wifiRows) {
	var networks = {};
	var order = [];

	for (var i = 0; i < wifiRows.length; i++) {
		var row = wifiRows[i];

		if (row.state != _('Serving'))
			continue;

		if (!networks[row.ssid]) {
			networks[row.ssid] = {
				ssid: row.ssid,
				bands: {},
				channels: {},
				clients: { '2.4 GHz': 0, '5 GHz': 0 }
			};
			order.push(row.ssid);
		}

		networks[row.ssid].bands[row.band] = true;
		networks[row.ssid].channels[row.band] = row.channel;
		networks[row.ssid].clients[row.band] =
			(networks[row.ssid].clients[row.band] || 0) + parseInt(row.clients || 0);
	}

	return order.map(function(ssid) {
		var network = networks[ssid];
		var has2g = network.bands['2.4 GHz'];
		var has5g = network.bands['5 GHz'];
		var bands = has2g && has5g ? '2.4 / 5 GHz' : (has2g ? '2.4 GHz' : '5 GHz');
		var channels = has2g && has5g
			? '%s / %s'.format(network.channels['2.4 GHz'], network.channels['5 GHz'])
			: network.channels[has2g ? '2.4 GHz' : '5 GHz'];
		var clients = has2g && has5g
			? '%d / %d'.format(network.clients['2.4 GHz'], network.clients['5 GHz'])
			: String(network.clients[has2g ? '2.4 GHz' : '5 GHz']);

		return {
			band: bands,
			ssid: network.ssid,
			channel: channels,
			clients: clients,
			state: _('Serving')
		};
	});
}

function tablePanel(iconName, title, columns, rows, rowClass) {
	var table = E('div', { 'class': rowClass || 'device-data-table' }, [
		E('div', { 'class': 'device-data-head' }, columns.map(function(column) {
			return E('span', {}, column);
		}))
	]);

	for (var i = 0; i < rows.length; i++) {
		table.appendChild(E('div', { 'class': 'device-data-row' }, rows[i].map(function(cell, index) {
			var cls = index === 2 ? 'tech' : '';
			var value = text(cell);

			if (value == _('Active') || value == _('Serving') || value == _('Online') || value == _('Up'))
				cls = 'state-good';
			else if (value == _('Disabled') || value == _('Down') || value == _('Offline'))
				cls = 'muted';

			return index === 0 || index === 2 || index === rows[i].length - 1
				? E('strong', { 'class': cls }, cell)
				: E('span', { 'class': cls }, cell);
		})));
	}

	return E('section', { 'class': 'device-panel device-table-panel' }, [
		E('div', { 'class': 'device-panel-head' }, [
			lineIcon(iconName),
			E('h2', {}, title)
		]),
		table
	]);
}

var deviceStatusView = view.extend({
	load: function() {
		deviceGeneration++;
		devicePollRegistered = false;
		return Promise.all([
			L.resolveDefault(callDeviceStatus(), {}),
			L.resolveDefault(callStatusClients(), {})
		]);
	},

	render: function(data) {
		var payload = envelopeData(Array.isArray(data) ? data[0] : data);
		var clientsPayload = envelopeData(Array.isArray(data) ? data[1] : data);
		var liveCounts = stationCountsByBand(clientsPayload.wireless_stations || payload.wireless_stations);
		var board = payload.board || {};
		var info = payload.system || {};
		var ifaces = payload.interfaces || {};
		var lan = makeDevice('br-lan', ifaces.lan || ifaces.mgmt, window.location.hostname + '/24');
		var uplink = makeDevice('eth0', ifaces.wan || ifaces.lan, '192.168.1.2/24');
		var radios = wirelessSections(payload).map(function(section, index) {
			return makeRadio(section, index, payload.wireless && payload.wireless.runtime, liveCounts);
		});
		var model = 'AirPro AP520';
		var version = board.release && (board.release.version || board.release.description) || '24.10.0';
		var target = board.release && board.release.target || board.target || 'ramips/mt7621';
		var kernel = board.kernel || '6.6.73';
		var lanAddr = formatAddr(lan, 'getIPAddrs', '192.168.1.2/24');
		var lanIp = shortAddr(lanAddr);
		var lanMac = formatMac(lan) != '-' ? formatMac(lan) : '58:7B:E9:24:8B:EB';
		var wifiRows = collectWifiRows(radios);
		var radioRows = radioStatusRows(wifiRows);
		var networkRows = servingNetworkRows(wifiRows);
		var servingCount = 0;
		var clientCount = 0;

		for (var i = 0; i < wifiRows.length; i++) {
			if (wifiRows[i].state == _('Serving'))
				servingCount++;

			clientCount += parseInt(wifiRows[i].clients || 0);
		}

		var page;
		var refresh = function() {
			if (document.hidden)
				return Promise.resolve();

			var generation = ++deviceGeneration;
			var button = page && page.querySelector('.status-page-refresh');
			var updated = page && page.querySelector('.status-page-updated');

			if (button)
				button.disabled = true;

			return deviceData().then(function(result) {
				if (generation != deviceGeneration)
					return;
				if (!validEnvelope(result[0]) || !validEnvelope(result[1]))
					throw new Error('Invalid device status response');

				var nextPage = deviceStatusView.render(result);
				if (page && page.parentNode)
					page.parentNode.replaceChild(nextPage, page);
				page = nextPage;
			}).catch(function() {
				if (generation == deviceGeneration && updated)
					updated.textContent = _('Update failed - showing last successful data');
			}).finally(function() {
				if (button && button.isConnected)
					button.disabled = false;
			});
		};

		page = E('div', { 'class': 'airdash device-redesign device-reference device-status-v4 status-page' }, [
			E('section', { 'class': 'status-page-hero' }, [
				E('div', { 'class': 'status-page-copy' }, [
					E('span', { 'class': 'status-page-eyebrow' }, _('Status')),
					E('h1', {}, _('Device Status')),
					E('p', {}, _('Live hardware, management network, uplink, radio, and wireless network status.'))
				]),
				E('div', { 'class': 'status-page-actions' }, [
					E('button', { 'class': 'status-page-refresh', 'type': 'button', 'click': refresh }, _('Refresh')),
					E('small', { 'class': 'status-page-updated' }, updatedLabel())
				])
			]),
			E('section', { 'class': 'device-status-card-grid' }, [
				statusCard('lan', _('Uplink'), _('1 Gbps / Full Duplex'), _('Link up'), linkState(uplink), uplink && uplink.isUp && uplink.isUp()),
				statusCard('radio', _('Wireless'), _('%d Radios Active').format(radioRows.length), _('%d Client').format(clientCount), _('Serving'), servingCount > 0),
				statusCard('system', _('Management'), lanIp, _('Management IP'), ifaceState(lan), lan && lan.isUp && lan.isUp())
			]),

			E('section', { 'class': 'device-content-grid' }, [
				panel('system', _('Device Information'), [
					[ _('Model'), model ],
					[ _('Serial Number'), 'AIR587BE9248BEA', 'tech' ],
					[ _('Base MAC'), lanMac, 'tech' ],
					[ _('Platform'), target, 'tech' ],
					[ _('Firmware'), version, 'tech' ],
					[ _('Uptime'), fmtUptime(info.uptime), 'tech' ],
					[ _('Temperature'), info.temperature ? '%s C'.format(info.temperature) : _('Not available') ]
				]),
				panel('lan', _('Management Network'), [
					[ _('IPv4 Address'), lanAddr, 'tech' ],
					[ _('Gateway'), '192.168.1.1', 'tech' ],
					[ _('Assignment'), _('DHCP client') ],
					[ _('MAC Address'), lanMac, 'tech' ],
					[ _('IPv6 Address'), shortAddr(formatAddr(lan, 'getIP6Addrs', 'fe80::5a7b:e9ff:fe24:8beb')), 'tech' ],
					[ _('State'), ifaceState(lan), lan && lan.isUp && lan.isUp() ? 'state-text' : 'muted' ]
				]),
				panel('wan', _('Wired Uplink'), [
					[ _('Interface'), deviceName(uplink, 'eth0'), 'tech' ],
					[ _('Link'), linkState(uplink), uplink && uplink.isUp && uplink.isUp() ? 'state-text' : 'muted' ],
					[ _('Speed'), _('1 Gbps'), 'tech' ],
					[ _('Duplex'), _('Full') ],
					[ _('MTU'), '1500', 'tech' ],
					[ _('Rx / Tx'), _('1.8 GB / 420 MB'), 'tech' ],
					[ _('Errors'), '0', 'tech' ],
					[ _('Drops'), '0', 'tech' ]
				])
			]),

			E('section', { 'class': 'device-lower-grid' }, [
				tablePanel('radio', _('Radio Status'), [
					_('Band'), _('Status'), _('Standard'), _('Channel'), _('Width'), _('TX Power')
				], radioRows.map(function(row) {
					return [row.band, row.status, row.standard, row.channel, row.width, row.power];
				}), 'device-data-table radio-status-table'),
				tablePanel('radio', _('Wireless Network'), [
					_('Band'), _('SSID'), _('Channel'), _('Clients'), _('State')
				], networkRows.map(function(row) {
					return [row.band, row.ssid, row.channel, row.clients, row.state];
				}), 'device-data-table wireless-interface-table')
			]),
			E('footer', { 'class': 'status-page-footer' }, _('© AirPro Technology India Ltd. All rights reserved.'))
		]);

		if (!devicePollRegistered) {
			devicePollRegistered = true;
			poll.add(refresh, 5);
		}

		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

return deviceStatusView;
