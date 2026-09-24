'use strict';
'require view';
'require fs';
'require rpc';
'require network';

var callDHCPLeases = rpc.declare({
	object: 'luci-rpc',
	method: 'getDHCPLeases',
	expect: { '': {} }
});

function leaseMap(data) {
	var map = {};
	var leases = Array.isArray(data.dhcp_leases) ? data.dhcp_leases : [];
	var leases6 = Array.isArray(data.dhcp6_leases) ? data.dhcp6_leases : [];

	for (var i = 0; i < leases.length; i++)
		if (leases[i].ipaddr || leases[i].ip)
			map[leases[i].ipaddr || leases[i].ip] = {
				ip: leases[i].ipaddr || leases[i].ip,
				mac: leases[i].macaddr || leases[i].mac || '-',
				host: leases[i].hostname || leases[i].host || '-'
			};

	for (var j = 0; j < leases6.length; j++)
		if (leases6[j].ip6addr || leases6[j].ip)
			map[leases6[j].ip6addr || leases6[j].ip] = {
				ip: leases6[j].ip6addr || leases6[j].ip,
				mac: leases6[j].macaddr || leases6[j].mac || '-',
				host: leases6[j].hostname || leases6[j].host || '-'
			};

	return map;
}

function parseNeigh(text, leases) {
	var rows = [];
	var seen = {};
	var lines = (text || '').trim().split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var m = lines[i].match(/^(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})\s+.*\s+(\S+)$/i);

		if (!m || m[4] == 'FAILED')
			continue;

		var key = m[1] + m[3];
		var lease = leases[m[1]] || {};

		if (seen[key])
			continue;

		seen[key] = true;
		rows.push([ m[1], m[3].toUpperCase(), lease.host || '-', m[2] ]);
	}

	return rows;
}

function table(title, headers, rows) {
	return E('div', { 'class': 'air-card air-table-card' }, [
		E('div', { 'class': 'air-card-head' }, [
			E('h3', {}, title),
			E('span', { 'class': 'air-refresh' })
		]),
		E('table', { 'class': 'table air-table' }, [
			E('tr', { 'class': 'tr table-titles' }, headers.map(function(h) {
				return E('th', { 'class': 'th' }, h);
			}))
		].concat(rows.length ? rows.map(function(row) {
			return E('tr', { 'class': 'tr' }, row.map(function(cell) {
				return E('td', { 'class': 'td' }, cell);
			}));
		}) : [
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td air-empty', 'colspan': headers.length }, _('There are no records in the list'))
			])
		])),
		E('div', { 'class': 'air-table-foot' }, '0-%d / %d'.format(rows.length, rows.length))
	]);
}

return view.extend({
	load: function() {
		return network.getWifiNetworks().then(function(wifiNets) {
			var assocTasks = wifiNets.map(function(net) {
				return L.resolveDefault(net.getAssocList(), []).then(function(list) {
					net.assoclist = list;
					return net;
				});
			});

			return Promise.all([
				L.resolveDefault(callDHCPLeases(), {}),
				L.resolveDefault(fs.exec('/sbin/ip', [ '-4', 'neigh', 'show' ]), {}),
				L.resolveDefault(fs.exec('/sbin/ip', [ '-6', 'neigh', 'show' ]), {}),
				Promise.all(assocTasks)
			]);
		});
	},

	render: function(data) {
		var leases = leaseMap(data[0] || {});
		var lanRows = parseNeigh((data[1].stdout || '') + '\n' + (data[2].stdout || ''), leases);
		var wlanRows = [];
		var wifiNets = data[3] || [];

		for (var i = 0; i < wifiNets.length; i++) {
			var net = wifiNets[i];
			var list = net.assoclist || [];
			var ssid = net.getSSID ? (net.getSSID() || net.getName()) : '-';
			var ifname = net.getIfname ? net.getIfname() : '-';

			for (var j = 0; j < list.length; j++) {
				var sta = list[j] || {};
				var mac = (sta.mac || '').toUpperCase();
				var ip = '-';
				var host = '-';

				for (var leaseIp in leases) {
					if ((leases[leaseIp].mac || '').toUpperCase() == mac) {
						ip = leases[leaseIp].ip || leaseIp;
						host = leases[leaseIp].host || '-';
						break;
					}
				}

				wlanRows.push([
					ssid,
					mac || '-',
					ip,
					host,
					ifname,
					(sta.signal != null && sta.noise != null) ? '%d/%d dBm'.format(sta.signal, sta.noise) : '-',
					'-'
				]);
			}
		}

		return E('div', { 'class': 'air-page' }, [
			E('h2', {}, _('Clients')),
			table(_('List of LAN Clients'),
				[ _('IP Address (IPv4, IPv6)'), _('MAC Address'), _('Host Name'), _('Interface'), _('Actions') ],
				lanRows.map(function(row) { return [ row[0], row[1], row[2], row[3], '-' ]; })),
			table(_('List of WLAN Clients'),
				[ _('SSID'), _('MAC Address'), _('IP Address'), _('Host Name'), _('Radio (Frequency)'), _('Signal'), _('Actions') ],
				wlanRows)
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
