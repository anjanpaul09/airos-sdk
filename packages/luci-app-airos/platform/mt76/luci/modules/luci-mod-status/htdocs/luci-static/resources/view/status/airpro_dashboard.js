'use strict';
'require view';
'require fs';
'require poll';
'require rpc';
'require network';

var callBoard = rpc.declare({ object: 'system', method: 'board' });
var callInfo = rpc.declare({ object: 'system', method: 'info' });
var callDHCPLeases = rpc.declare({
	object: 'luci-rpc',
	method: 'getDHCPLeases',
	expect: { '': {} }
});

function fmtBytes(v) {
	return '%1024.2mB'.format(v || 0);
}

var lastCpu = null;

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

function cpuPercent(stat) {
	var current = cpuSnapshot(stat);
	var prev = lastCpu || current;
	var user = Math.max(0, current.user - prev.user);
	var kernel = Math.max(0, current.kernel - prev.kernel);
	var idle = Math.max(0, current.idle - prev.idle);
	var other = Math.max(0, current.other - prev.other);
	var total = user + kernel + idle + other;

	lastCpu = current;

	if (total <= 0) {
		return [
			{ label: _('Idle'), value: 100, color: '#10b981' },
			{ label: _('User'), value: 0, color: '#5eead4' },
			{ label: _('Kernel'), value: 0, color: '#38bdf8' },
			{ label: _('Other'), value: 0, color: '#cbd5e1' }
		];
	}

	return [
		{ label: _('Idle'), value: Math.round(idle * 100 / total), color: '#10b981' },
		{ label: _('User'), value: Math.round(user * 100 / total), color: '#5eead4' },
		{ label: _('Kernel'), value: Math.round(kernel * 100 / total), color: '#38bdf8' },
		{ label: _('Other'), value: Math.max(0, 100 - Math.round((idle + user + kernel) * 100 / total)), color: '#cbd5e1' }
	];
}

function pieData(items) {
	var offset = 0;
	var parts = [];

	for (var i = 0; i < items.length; i++) {
		var next = offset + items[i].value;
		parts.push('%s %d%% %d%%'.format(items[i].color, offset, next));
		offset = next;
	}

	return 'conic-gradient(%s)'.format(parts.join(', '));
}

function updatePie(root, items) {
	var pie = root.querySelector('.air-pie');
	var legend = root.querySelector('.air-legend');
	var value = root.querySelector('.air-pie-value');

	pie.style.background = pieData(items);
	if (value)
		value.textContent = keyPercent(items);
	legend.innerHTML = '';

	for (var i = 0; i < items.length; i++) {
		legend.appendChild(E('div', {}, [
			E('i', { 'style': 'background:%s'.format(items[i].color) }),
			E('strong', {}, '%d%% %s'.format(items[i].value, items[i].label))
		]));
	}
}

function keyPercent(items) {
	if (!items || !items.length)
		return '0%';

	if (items[0].label === _('Idle'))
		return '%d%%'.format(Math.max(0, 100 - items[0].value));

	return '%d%%'.format(items[0].value || 0);
}

function donutCard(id, title, items) {
	return E('div', { 'class': 'air-card air-card-chart', 'id': id }, [
		E('div', { 'class': 'air-card-head' }, [
			E('h3', {}, title),
			E('span', { 'class': 'air-refresh' })
		]),
		E('div', { 'class': 'air-chart-row' }, [
			E('div', { 'class': 'air-pie', 'style': 'background:%s'.format(pieData(items)) }, [
				E('span', { 'class': 'air-pie-value' }, keyPercent(items))
			]),
			E('div', { 'class': 'air-legend' }, items.map(function(item) {
				return E('div', {}, [
					E('i', { 'style': 'background:%s'.format(item.color) }),
					E('strong', {}, '%d%% %s'.format(item.value, item.label))
				]);
			}))
		])
	]);
}

function metricChip(label, value, tone) {
	return E('div', { 'class': 'air-metric-chip air-metric-%s'.format(tone || 'blue') }, [
		E('span', {}, label),
		E('strong', {}, value || '-')
	]);
}

function detailCard(title, rows, chips, cardClass) {
	return E('div', { 'class': 'air-card %s'.format(cardClass || '') }, [
		E('div', { 'class': 'air-card-head' }, [
			E('h3', {}, title),
			E('button', {
				'class': 'air-refresh',
				'click': function(ev) {
					var card = ev.currentTarget.closest('.air-card');
					card.classList.toggle('is-collapsed');
				}
			})
		]),
		chips && chips.length ? E('div', { 'class': 'air-metric-row' }, chips.map(function(chip) {
			return metricChip(chip[0], chip[1], chip[2]);
		})) : '',
		E('div', { 'class': 'air-detail-list' }, rows.map(function(row) {
			return E('div', {}, [
				E('label', {}, row[0]),
				E('strong', {}, row[1] || '-')
			]);
		}))
	]);
}

function summaryCard(title, value, note, tone) {
	return E('div', { 'class': 'air-summary air-summary-%s'.format(tone || 'blue') }, [
		E('i', { 'class': 'air-summary-status' }),
		E('span', {}, title),
		E('strong', {}, value),
		E('small', {}, note || '-')
	]);
}

function topologyCard(model, devices, ssid24, ssid5) {
	return E('div', { 'class': 'router-console-card' }, [
		E('div', { 'class': 'router-console-head' }, [
			E('div', { 'class': 'router-tabs' }, [
				E('span', { 'class': 'active' }, _('Status')),
				E('span', {}, _('Settings')),
				E('span', {}, _('Advanced')),
				E('span', {}, _('Storage'))
			]),
			E('button', { 'class': 'speed-test-btn' }, _('Speed Test'))
		]),
		E('div', { 'class': 'router-topology' }, [
			E('div', { 'class': 'topology-node topology-devices' }, [
				E('div', { 'class': 'node-visual devices-visual' }, [
					E('i'), E('i'), E('i')
				]),
				E('strong', {}, _('Devices')),
				E('small', {}, _('%d Devices').format(devices))
			]),
			E('div', { 'class': 'topology-link topology-link-left' }),
			E('div', { 'class': 'topology-node topology-router' }, [
				E('div', { 'class': 'node-visual router-visual' }, [
					E('i'), E('i'), E('i')
				]),
				E('strong', {}, model || _('Wi-Fi Router')),
				E('div', { 'class': 'router-ssids' }, [
					E('span', {}, ssid24 || '2.4G: -'),
					E('span', {}, ssid5 || '5G: -')
				])
			]),
			E('div', { 'class': 'topology-link topology-link-right' }),
			E('div', { 'class': 'topology-node topology-internet' }, [
				E('div', { 'class': 'node-visual internet-visual' }),
				E('strong', {}, _('Internet')),
				E('small', {}, _('100M Bandwidth'))
			])
		]),
		E('div', { 'class': 'router-console-foot' }, [
			E('span', {}, _('Router online')),
			E('a', { 'href': L.url('admin/status/devices') }, _('Network map'))
		])
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
				L.resolveDefault(callBoard(), {}),
				L.resolveDefault(callInfo(), {}),
				L.resolveDefault(fs.read('/proc/stat'), ''),
				Promise.all(assocTasks),
				L.resolveDefault(callDHCPLeases(), {})
			]);
		});
	},

	render: function(data) {
		var board = data[0] || {};
		var info = data[1] || {};
		var mem = info.memory || {};
		lastCpu = cpuSnapshot(data[2]);

		var cpu = [
			{ label: _('Idle'), value: 100, color: '#10b981' },
			{ label: _('User'), value: 0, color: '#5eead4' },
			{ label: _('Kernel'), value: 0, color: '#38bdf8' },
			{ label: _('Other'), value: 0, color: '#cbd5e1' }
		];
		var used = mem.total && mem.free ? mem.total - mem.free : 0;
		var free = mem.total ? Math.max(0, mem.total - used) : 0;
		var memory = [
			{ label: _('Current Usage'), value: mem.total ? Math.round(used * 100 / mem.total) : 0, color: '#10b981' },
			{ label: _('Free'), value: mem.total ? Math.round(free * 100 / mem.total) : 0, color: '#d9f99d' }
		];
		var radios = data[3] || [];
		var leaseInfo = data[4] || {};
		var dhcpLeases = Array.isArray(leaseInfo.dhcp_leases) ? leaseInfo.dhcp_leases : [];
		var associatedClients = 0;
		var upRadios = 0;

		for (var ri = 0; ri < radios.length; ri++) {
			associatedClients += (radios[ri].assoclist || []).length;

			if (!radios[ri].isDisabled || !radios[ri].isDisabled())
				upRadios++;
		}

		var ssid24 = radios[0] ? (radios[0].getSSID ? radios[0].getSSID() : radios[0].getName()) : '-';
		var ssid5 = radios[1] ? (radios[1].getSSID ? radios[1].getSSID() : radios[1].getName()) : '-';
		var deviceCount = Math.max(dhcpLeases.length, associatedClients);

		var page = E('div', { 'class': 'air-page' }, [
			E('h2', { 'class': 'air-title-live' }, [
				_('Dashboard'),
				E('span', { 'class': 'title-live-dot' }, _('Live'))
			]),
			topologyCard(board.model || 'AirPro Router', deviceCount, ssid24, ssid5),
			E('div', { 'class': 'air-summary-row' }, [
				summaryCard(_('Internet'), _('Online'), _('Gateway reachable'), 'green'),
				summaryCard(_('Clients'), String(deviceCount), _('%d Wi-Fi associated').format(associatedClients), 'blue'),
				summaryCard(_('Wi-Fi'), '%d/%d'.format(upRadios, radios.length), _('Active radios'), 'cyan'),
				summaryCard(_('Uptime'), info.uptime ? '%t'.format(info.uptime) : '-', _('Since last boot'), 'violet')
			]),
			E('div', { 'class': 'air-grid air-grid-2' }, [
				donutCard('air-cpu-card', _('CPU Utilisation'), cpu),
				donutCard('air-memory-card', _('Memory Utilisation'), memory),
				detailCard(_('System Details'), [
					[ _('Model Name'), board.model || 'AirPro Home Gateway' ],
					[ _('2.4 GHz SSID'), ssid24 ],
					[ _('5 GHz SSID'), ssid5 ],
					[ _('Memory'), mem.total ? '%s / %s'.format(fmtBytes(used), fmtBytes(mem.total)) : '-' ]
				], [
					[ _('Firmware'), board.release && board.release.version || 'OpenWrt', 'blue' ],
					[ _('Platform'), board.release && board.release.target || '-', 'cyan' ],
					[ _('Kernel'), board.kernel || '-', 'violet' ]
				]),
				detailCard(_('Storage Devices'), [
					[ _('Status'), _('No connected storage devices') ],
					[ _('Kernel'), board.kernel || '-' ],
					[ _('Target'), board.release && board.release.target || '-' ]
				], [
					[ _('USB'), _('None'), 'muted' ],
					[ _('Disk'), _('Not mounted'), 'orange' ],
					[ _('Health'), _('Ready'), 'green' ]
				], 'air-card-storage')
			])
		]);

		poll.add(function() {
			return Promise.all([
				L.resolveDefault(fs.read('/proc/stat'), ''),
				L.resolveDefault(callInfo(), {})
			]).then(function(result) {
				var nextCpu = cpuPercent(result[0]);
				var nextInfo = result[1] || {};
				var nextMem = nextInfo.memory || {};
				var nextUsed = nextMem.total && nextMem.free ? nextMem.total - nextMem.free : 0;
				var nextFree = nextMem.total ? Math.max(0, nextMem.total - nextUsed) : 0;
				var nextMemory = [
					{ label: _('Current Usage'), value: nextMem.total ? Math.round(nextUsed * 100 / nextMem.total) : 0, color: '#10b981' },
					{ label: _('Free'), value: nextMem.total ? Math.round(nextFree * 100 / nextMem.total) : 0, color: '#d9f99d' }
				];

				updatePie(document.getElementById('air-cpu-card'), nextCpu);
				updatePie(document.getElementById('air-memory-card'), nextMemory);
			});
		}, 3);

		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
