'use strict';
'require view';

function bandHeader(label, ssid, speed, tone) {
	return E('div', { 'class': 'devices-band-head' }, [
		E('div', {}, [
			E('div', { 'class': 'devices-band-title' }, [
				E('strong', {}, label),
				E('span', { 'class': 'network-name' }, [
					E('i'),
					ssid
				]),
				E('em', { 'class': 'speed-pill speed-%s'.format(tone || 'green') }, speed)
			])
		]),
		E('span', { 'class': 'access-label' }, _('Internet access'))
	]);
}

function deviceIcon(type, label) {
	return E('div', { 'class': 'device-icon device-icon-%s'.format(type || 'generic') }, label || '');
}

function toggle(on) {
	return E('button', {
		'class': 'device-toggle %s'.format(on ? 'on' : 'off'),
		'aria-label': on ? _('Internet access enabled') : _('Internet access disabled')
	}, [
		E('span')
	]);
}

function deviceRow(device) {
	return E('div', { 'class': 'device-row %s'.format(device.unknown ? 'unknown' : '') }, [
		deviceIcon(device.type, device.icon),
		E('div', { 'class': 'device-copy' }, [
			E('strong', {}, device.name),
			E('small', {}, '%s  ·  IP: %s'.format(device.duration, device.ip))
		]),
		toggle(device.enabled)
	]);
}

function bandColumn(label, ssid, speed, tone, devices, tip) {
	return E('section', { 'class': 'devices-band-card' }, [
		bandHeader(label, ssid, speed, tone),
		E('div', { 'class': 'devices-list' }, devices.map(deviceRow)),
		E('div', { 'class': 'band-helper' }, [
			E('div', { 'class': 'band-helper-orb' }, label.replace('G', '')),
			E('p', {}, tip)
		])
	]);
}

return view.extend({
	render: function() {
		var devices24 = [
			{ name: 'Apple iPhone 11 Pro', duration: 'Connected: 1h 22m', ip: '192.168.88.32', type: 'apple', icon: 'A', enabled: true },
			{ name: 'Google Home', duration: 'Connected: 8h 43m', ip: '192.168.88.122', type: 'google', icon: 'G', enabled: true },
			{ name: 'Unknown', duration: 'Connected: 3d 5h 17m', ip: '192.168.88.145', type: 'unknown', icon: '?', enabled: false, unknown: true }
		];

		var devices5 = [
			{ name: 'Apple MacBook Pro', duration: 'Connected: 1d 12h 5m', ip: '192.168.88.48', type: 'apple', icon: 'A', enabled: true },
			{ name: 'Sony Bravia G950 4K', duration: 'Connected: 1h 32m', ip: '192.168.88.122', type: 'sony', icon: 'S', enabled: true }
		];

		return E('div', { 'class': 'devices-page' }, [
			E('div', { 'class': 'devices-shell' }, [
				E('nav', { 'class': 'devices-topnav' }, [
					E('div', { 'class': 'devices-tabs' }, [
						E('span', { 'class': 'active' }, _('Status')),
						E('span', {}, _('Settings')),
						E('span', {}, _('Advanced')),
						E('span', {}, _('Storage'))
					]),
					E('a', { 'class': 'devices-speed-test', 'href': '#' }, [
						E('i'),
						_('Speed Test')
					])
				]),
				E('div', { 'class': 'devices-title-row' }, [
					E('div', { 'class': 'devices-title' }, [
						E('a', { 'class': 'devices-back', 'href': L.url('admin/status/overview') }, '‹'),
						E('h2', {}, _('Devices')),
						E('span', { 'class': 'devices-count' }, '5')
					]),
					E('button', { 'class': 'find-device-btn' }, _('Find new device'))
				]),
				E('div', { 'class': 'devices-band-grid' }, [
					bandColumn('2.4G', 'MyRouter', '290 KB/s', 'neutral', devices24, _('2.4GHz reaches farther and is better for distant or low-power devices.')),
					bandColumn('5G', 'MyRouter_5G', '867 KB/s', 'brand', devices5, _('5GHz is faster for devices near the router.'))
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
