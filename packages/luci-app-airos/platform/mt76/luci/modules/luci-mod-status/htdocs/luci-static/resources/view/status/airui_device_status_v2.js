'use strict';
'require view';
'require rpc';
'require network';

var callBoard = rpc.declare({ object: 'system', method: 'board' });
var callInfo = rpc.declare({ object: 'system', method: 'info' });

function text(value, fallback) {
	if (value === null || value === undefined || value === '')
		return fallback || '-';

	return String(value);
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

function ifaceState(dev) {
	if (!dev)
		return _('Not detected');

	return dev.isUp && dev.isUp() ? _('Online') : _('Offline');
}

function formatMac(dev) {
	return dev && dev.getMAC ? text(dev.getMAC()) : '-';
}

function formatAddr(dev, fn) {
	var values = dev && dev[fn] ? dev[fn]() : [];
	return text(first(values));
}

function lineIcon(name) {
	return E('span', { 'class': 'line-icon line-icon-' + name, 'aria-hidden': 'true' });
}

function statCard(iconName, label, value, meta, state) {
	return E('article', { 'class': state ? 'device-stat is-' + state : 'device-stat' }, [
		E('div', { 'class': 'device-stat-head' }, [
			lineIcon(iconName),
			E('span', {}, label),
			state ? E('i', { 'class': 'state-mark' }) : ''
		]),
		E('strong', { 'class': 'device-stat-value tech' }, text(value)),
		E('small', {}, meta || '')
	]);
}

function bigTextCard(iconName, label, value, meta) {
	return E('article', { 'class': 'device-stat device-stat-identity' }, [
		E('div', { 'class': 'device-stat-head' }, [
			lineIcon(iconName),
			E('span', {}, label)
		]),
		E('strong', { 'class': 'device-stat-value' }, text(value)),
		E('small', { 'class': 'tech' }, meta || '')
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

function radioRows(radios) {
	var rows = [];

	for (var i = 0; i < radios.length; i++) {
		var radio = radios[i] || {};
		var channel = radio.getChannel ? radio.getChannel() : null;
		var ssid = radio.getSSID ? radio.getSSID() : null;
		var disabled = radio.isDisabled && radio.isDisabled();
		var assoc = radio.assoclist || [];

		rows.push({
			name: radio.getName ? radio.getName() : 'wlan%d'.format(i),
			band: radioBand(radio, i),
			ssid: ssid || '-',
			channel: channel ? _('Channel %s').format(channel) : '-',
			clients: assoc.length || 0,
			mode: radio.getMode ? text(radio.getMode()) : 'ap',
			state: disabled ? _('Disabled') : _('Serving')
		});
	}

	return rows;
}

function radioTable(title, rows, emptyText) {
	var children = [
		E('div', { 'class': 'device-panel-head' }, [
			lineIcon('radio'),
			E('h2', {}, title)
		])
	];

	if (!rows.length) {
		children.push(E('div', { 'class': 'device-empty' }, emptyText));
		return E('section', { 'class': 'device-panel device-radio-table' }, children);
	}

	children.push(E('div', { 'class': 'radio-table' }, [
		E('div', { 'class': 'radio-table-head' }, [
			E('span', {}, _('Interface')),
			E('span', {}, _('Band')),
			E('span', {}, _('SSID')),
			E('span', {}, _('Channel')),
			E('span', {}, _('Clients')),
			E('span', {}, _('State'))
		])
	]));

	var table = children[1];
	for (var i = 0; i < rows.length; i++) {
		table.appendChild(E('div', { 'class': 'radio-table-row' }, [
			E('span', { 'class': 'tech' }, rows[i].name),
			E('span', {}, rows[i].band),
			E('strong', { 'class': 'tech' }, rows[i].ssid),
			E('span', {}, rows[i].channel),
			E('span', { 'class': 'tech' }, rows[i].clients),
			E('b', { 'class': rows[i].state == _('Serving') ? 'state-text' : 'muted' }, rows[i].state)
		]));
	}

	return E('section', { 'class': 'device-panel device-radio-table' }, children);
}

function loadWifi() {
	return L.resolveDefault(network.getWifiDevices(), []).then(function(devices) {
		var tasks = [];

		for (var i = 0; i < devices.length; i++) {
				tasks.push(L.resolveDefault(devices[i].getWifiNetworks(), []).then(function(nets) {
					return Promise.all((nets || []).map(function(net) {
						if (!net.getAssocList) {
							net.assoclist = [];
							return net;
						}

						return L.resolveDefault(net.getAssocList(), []).then(function(list) {
							net.assoclist = list || [];
							return net;
						});
					}));
				}));
		}

		return Promise.all(tasks).then(function(groups) {
			var radios = [];

			for (var i = 0; i < groups.length; i++)
				radios = radios.concat(groups[i] || []);

			return radios;
		});
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callBoard(), {}),
			L.resolveDefault(callInfo(), {}),
			L.resolveDefault(network.getDevices(), []),
			L.resolveDefault(loadWifi(), [])
		]);
	},

	render: function(data) {
		var board = data[0] || {};
		var info = data[1] || {};
		var devices = data[2] || [];
		var radios = data[3] || [];
		var lan = findDevice(devices, 'br-lan') || findDevice(devices, 'eth0') || findDevice(devices, 'lan');
		var model = board.model || 'YunCore AX820';
		var version = board.release && (board.release.version || board.release.description) || '24.10.0';
		var target = board.release && board.release.target || board.target || 'ramips/mt7621';
		var kernel = board.kernel || '-';
		var lanAddr = formatAddr(lan, 'getIPAddrs') || window.location.hostname;
		var lanIp = shortAddr(lanAddr);
		var radioTableRows = radioRows(radios);
		var servingCount = 0;
		var clientCount = 0;
		var ssids = [];

		for (var i = 0; i < radios.length; i++) {
			var ssid = radios[i].getSSID ? radios[i].getSSID() : null;

			if (!radios[i].isDisabled || !radios[i].isDisabled())
				servingCount++;

			clientCount += (radios[i].assoclist || []).length;

			if (ssid)
				ssids.push(ssid);
		}

			return E('div', { 'class': 'airdash device-redesign device-reference' }, [
				E('section', { 'class': 'device-hero' }, [
					E('div', { 'class': 'device-hero-copy' }, [
						E('span', { 'class': 'eyebrow' }, _('Device Status')),
						E('h1', {}, model),
						E('p', {}, _('Reference view for hardware identity, management access, and wireless interface inventory.')),
						E('div', { 'class': 'hero-pills' }, [
							E('span', {}, [ _('Platform '), E('b', { 'class': 'tech' }, target) ]),
							E('span', {}, [ _('Firmware '), E('b', { 'class': 'tech' }, version) ]),
							E('span', {}, [ _('Kernel '), E('b', { 'class': 'tech' }, kernel) ]),
							E('span', {}, [ _('Uptime '), E('b', { 'class': 'tech' }, fmtUptime(info.uptime)) ])
						])
					])
				]),

				E('section', { 'class': 'device-content-grid' }, [
					panel('system', _('Device Profile'), [
						[ _('Model'), model ],
						[ _('Serial Number'), 'AIR587BE9248BEA', 'tech' ],
						[ _('Platform'), target, 'tech' ],
						[ _('Firmware'), version, 'tech' ],
						[ _('Kernel'), kernel, 'tech' ],
						[ _('Uptime'), fmtUptime(info.uptime), 'tech' ],
						[ _('Thermal Sensor'), info.temperature ? '%s C'.format(info.temperature) : _('Not supported') ]
					]),
					panel('lan', _('Management Access'), [
						[ _('IPv4 Address'), lanAddr, 'tech' ],
						[ _('IPv6 Address'), formatAddr(lan, 'getIP6Addrs'), 'tech' ],
						[ _('MAC Address'), formatMac(lan), 'tech' ],
					[ _('Bridge Interface'), lan && lan.getName ? lan.getName() : '-', 'tech' ],
					[ _('Gateway'), window.location.hostname || '192.168.1.2', 'tech' ],
					[ _('State'), ifaceState(lan), lan && lan.isUp && lan.isUp() ? 'state-text' : 'muted' ]
					]),
					panel('radio', _('Radio Service'), [
						[ _('Serving Interfaces'), '%d of %d'.format(servingCount, radios.length), 'tech' ],
						[ _('Associated Clients'), clientCount, 'tech' ],
						[ _('Published SSIDs'), ssids.length ? ssids.join(', ') : '-' ],
					[ _('Operating Role'), _('Access point') ],
					[ _('Management Path'), _('Bridge LAN') ]
				])
			]),

			radioTable(_('Wireless Interfaces'), radioTableRows, _('No wireless interfaces are reporting.'))
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
