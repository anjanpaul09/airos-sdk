'use strict';
'require view';
'require fs';
'require rpc';
'require network';
'require ui';

var callDHCPLeases = rpc.declare({
	object: 'luci-rpc',
	method: 'getDHCPLeases',
	expect: { '': {} }
});

function text(value, fallback) {
	if (value === null || value === undefined || value === '')
		return fallback || '-';

	return String(value);
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
			type: iface == 'br-lan' || iface.indexOf('eth') == 0 ? _('Wired') : _('LAN'),
			link: '-',
			state: m[4]
		});
	}

	return rows;
}

function isDirectWiredClient(client) {
	var iface = text(client && client.iface, '').toLowerCase();

	if (!iface)
		return false;

	if (iface == 'br-lan' || iface == 'wan' || iface == 'br-nat')
		return false;

	if (iface.indexOf('wlan') == 0 || iface.indexOf('phy') == 0)
		return false;

	return iface == 'br-mgmt' || iface == 'lan' || iface.indexOf('eth') == 0;
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
			var nets = [];

			for (var i = 0; i < groups.length; i++)
				nets = nets.concat(groups[i] || []);

			return nets;
		});
	});
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
		'click': function() {
			ui.addNotification(null, E('p', {}, _('Disconnect action is not wired yet for %s.').format(text(client.host, client.mac))), 'info');
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
		return Promise.all([
			L.resolveDefault(callDHCPLeases(), {}),
			L.resolveDefault(fs.exec('/sbin/ip', [ '-4', 'neigh', 'show' ]), {}),
			L.resolveDefault(fs.exec('/sbin/ip', [ '-6', 'neigh', 'show' ]), {}),
			L.resolveDefault(loadWifi(), [])
		]);
	},

	render: function(data) {
		var leases = leaseMap(data[0] || {});
		var lanRows = parseNeigh((data[1].stdout || '') + '\n' + (data[2].stdout || ''), leases);
		var wifiRows = [];
		var nets = data[3] || [];
		var seenWireless = {};

		for (var i = 0; i < nets.length; i++) {
			var net = nets[i];
			var assoc = net.assoclist || [];
			var ssid = net.getSSID ? (net.getSSID() || net.getName()) : '-';
			var ifname = net.getIfname ? net.getIfname() : (net.getName ? net.getName() : '-');

			for (var j = 0; j < assoc.length; j++) {
				var sta = assoc[j] || {};
				var mac = (sta.mac || '').toUpperCase();
				var lease = leases[mac] || {};
				var link = sta.signal != null ? '%d dBm'.format(sta.signal) : '-';

				seenWireless[mac] = true;
					wifiRows.push({
						host: lease.host || '-',
						ip: lease.ip || '-',
						mac: mac || '-',
						iface: ssid,
						type: _('Wireless'),
						link: link,
						rssi: link,
						duration: sta.connected_time ? fmtDuration(sta.connected_time) : _('Connected now'),
						linkType: sta.mlo ? 'MLO' : 'Non-MLO',
						state: _('Associated'),
						ifname: ifname
					});
			}
		}

		lanRows = lanRows.filter(function(client) {
			return isDirectWiredClient(client) && !seenWireless[(client.mac || '').toUpperCase()];
		});

		var total = lanRows.length + wifiRows.length;

		return E('div', { 'class': 'airdash clients-page' }, [
			E('section', { 'class': 'clients-hero' }, [
				E('div', {}, [
					E('span', { 'class': 'eyebrow' }, _('Clients')),
					E('h1', {}, _('Connected Clients')),
					E('p', {}, _('Live directly connected wired clients and associated Wi-Fi stations discovered from DHCP, neighbor, and radio association data.'))
				]),
				E('button', {
					'class': 'clients-refresh',
					'type': 'button',
					'click': function() { window.location.reload(); }
				}, _('Refresh'))
			]),
			E('section', { 'class': 'client-stats' }, [
				stat(_('Total'), total, _('known clients'), total > 0),
				stat(_('Wireless'), wifiRows.length, _('associated stations'), wifiRows.length > 0),
				stat(_('Wired Clients'), lanRows.length, _('directly connected to AP'), lanRows.length > 0)
			]),
				wifiTable(_('Associated Wi-Fi Stations'), wifiRows, _('No associated Wi-Fi stations are reporting.')),
				table(_('Wired Clients'), lanRows, _('No directly connected wired clients are reporting.'))
			]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
