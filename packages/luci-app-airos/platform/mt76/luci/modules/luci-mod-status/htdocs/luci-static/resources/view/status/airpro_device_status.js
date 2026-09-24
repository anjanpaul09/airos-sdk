'use strict';
'require view';
'require rpc';
'require network';

var callBoard = rpc.declare({ object: 'system', method: 'board' });

function card(title, rows) {
	return E('div', { 'class': 'air-card' }, [
		E('div', { 'class': 'air-card-head' }, [
			E('h3', {}, title),
			E('span', { 'class': 'air-refresh' })
		]),
		E('div', { 'class': 'air-detail-list' }, rows.map(function(row) {
			return E('div', {}, [
				E('label', {}, row[0]),
				E('strong', {}, row[1] || '-')
			]);
		}))
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callBoard(), {}),
			network.getDevices(),
			network.getWANNetworks(),
			network.getWAN6Networks(),
			network.getWifiDevices()
		]);
	},

	render: function(data) {
		var board = data[0] || {};
		var devices = data[1] || [];
		var wan = data[2][0];
		var wan6 = data[3][0];
		var wifi = data[4] || [];
		var lan = null;

		for (var i = 0; i < devices.length; i++)
			if (devices[i].getName && devices[i].getName() == 'br-lan')
				lan = devices[i];

		return E('div', { 'class': 'air-page' }, [
			E('h2', {}, _('Device Status')),
			E('div', { 'class': 'air-grid air-grid-2' }, [
				card(_('System Information'), [
					[ _('Firmware Version'), board.release && board.release.description || '-' ],
					[ _('Hardware Version'), board.model || '-' ],
					[ _('Serial Number'), 'AIR587BE9248BEA' ],
					[ _('Model Name'), 'AirPro Home Gateway' ]
				]),
				card(_('LAN Information'), [
					[ _('MAC Address'), lan && lan.getMAC ? lan.getMAC() : '-' ],
					[ _('IPv4 IP Address'), lan && lan.getIPAddrs ? (lan.getIPAddrs()[0] || '-') : '-' ],
					[ _('IPv6 IP Address'), lan && lan.getIP6Addrs ? (lan.getIP6Addrs()[0] || '-') : '-' ],
					[ _('IPv4 DHCP Server'), E('span', { 'class': 'air-ok' }, [ _('Enabled') ]) ]
				]),
				card(_('WAN Information'), [
					[ _('IPv4 Protocol'), wan && wan.getI18n ? wan.getI18n() : '-' ],
					[ _('IPv4 Address'), wan && wan.getIPAddrs ? (wan.getIPAddrs()[0] || '-') : '-' ],
					[ _('IPv6 Protocol'), wan6 && wan6.getI18n ? wan6.getI18n() : '-' ],
					[ _('IPv6 Address'), wan6 && wan6.getIP6Addrs ? (wan6.getIP6Addrs()[0] || '-') : '-' ]
				]),
				card(_('Wireless Information (Wireless LAN1)'), [
					[ _('Operating Frequency'), wifi[0] ? '2.4 GHz' : '-' ],
					[ _('Radio'), wifi[0] && wifi[0].getName ? wifi[0].getName() : '-' ]
				]),
				card(_('Wireless Information (Wireless LAN2)'), [
					[ _('Operating Frequency'), wifi[1] ? '5 GHz' : '-' ],
					[ _('Radio'), wifi[1] && wifi[1].getName ? wifi[1].getName() : '-' ]
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
