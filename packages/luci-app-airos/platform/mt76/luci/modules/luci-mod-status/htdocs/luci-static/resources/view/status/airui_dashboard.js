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

var lastCpu = null;

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
		E('span', { 'class': active ? 'status-dot is-active' : 'status-dot' }),
		E('div', { 'class': 'label' }, label),
		E('div', { 'class': 'value' }, value || '-'),
		E('div', { 'class': 'sub' }, subtext || '')
	]);
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

return view.extend({
	load: function() {
		var wifiTask = L.resolveDefault(network.getWifiDevices(), []).then(function(devices) {
			var tasks = [];

			for (var i = 0; i < devices.length; i++) {
				tasks.push(L.resolveDefault(devices[i].getWifiNetworks(), []).then(function(nets) {
					return Promise.all((nets || []).map(function(net) {
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

		return Promise.all([
			L.resolveDefault(callBoard(), {}),
			L.resolveDefault(callInfo(), {}),
			L.resolveDefault(fs.read('/proc/stat'), ''),
			L.resolveDefault(wifiTask, []),
			L.resolveDefault(callDHCPLeases(), {})
		]);
	},

	render: function(data) {
		var board = data[0] || {};
		var info = data[1] || {};
		var mem = info.memory || {};
		var radios = data[3] || [];
		var leases = data[4] && Array.isArray(data[4].dhcp_leases) ? data[4].dhcp_leases : [];
		var total = mem.total || 0;
		var free = mem.free || 0;
		var used = Math.max(0, total - free);
		var memPct = total ? Math.round(used * 100 / total) : 0;
		var cpuPct = cpuUsed(data[2]);
		var activeRadios = 0;
		var associatedClients = 0;

		for (var i = 0; i < radios.length; i++) {
			associatedClients += (radios[i].assoclist || []).length;

			if (!radios[i].isDisabled || !radios[i].isDisabled())
				activeRadios++;
		}

		var clients = Math.max(leases.length, associatedClients);
		var ssid24 = radios[0] ? (radios[0].getSSID ? radios[0].getSSID() : radios[0].getName()) : '-';
		var ssid5 = radios[1] ? (radios[1].getSSID ? radios[1].getSSID() : radios[1].getName()) : '-';
		var model = board.model || 'YunCore AX820';
		var target = board.release && board.release.target || board.target || 'ramips/mt7621';
		var version = board.release && board.release.version || '24.10.0';
		var load = info.load && info.load.length ? (info.load[0] / 65536).toFixed(2) : '0.00';
		var currentMode = _('Standalone');

		var page = E('div', { 'class': 'airdash' }, [
			E('div', { 'class': 'header-row' }, [
				E('div', { 'class': 'title' }, [
					E('h1', {}, _('Dashboard')),
					E('p', {}, [
						_('Overview of system performance, connectivity,'),
						E('br'),
						_('and hardware telemetry for node '),
						E('strong', {}, model + '.')
					])
				]),
				E('div', { 'class': 'local-ip' }, [
					E('div', { 'class': 'label' }, _('Local IP')),
					E('div', { 'class': 'value' }, window.location.hostname || '192.168.1.2')
				])
			]),
			E('section', { 'class': 'kpis' }, [
				kpi(_('Internet'), _('Online'), _('Gateway reachable'), true),
				kpi(_('Clients'), String(clients), _('Wi-Fi associated'), false),
				kpi(_('Wireless Interfaces'), E([], [ String(activeRadios), E('span', {}, ' / ' + (radios.length || 0)) ]), _('Active wireless interfaces'), false),
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
					[ _('Kernel'), board.kernel || '-' ],
					[ _('Current Mode'), currentMode ],
					[ _('Model Name'), model ],
					[ _('2.4 GHz SSID'), ssid24 ],
					[ _('5 GHz SSID'), ssid5 ]
				]),
				detailCard(_('Storage Devices'), [
					[ _('USB Interface'), _('None'), 'v muted' ],
					[ _('Disk Partition'), _('Not mounted'), 'v muted' ],
					[ _('Health'), _('Ready'), 'v good' ],
					[ _('Status'), _('No connected devices') ]
				])
			])
		]);

		poll.add(function() {
			return Promise.all([
				L.resolveDefault(fs.read('/proc/stat'), ''),
				L.resolveDefault(callInfo(), {})
			]).then(function(result) {
				var nextCpu = cpuUsed(result[0]);
				var nextMem = result[1] && result[1].memory || {};
				var nextTotal = nextMem.total || 0;
				var nextFree = nextMem.free || 0;
				var nextUsed = Math.max(0, nextTotal - nextFree);
				var nextMemPct = nextTotal ? Math.round(nextUsed * 100 / nextTotal) : 0;

				updateDonut(document.getElementById('airdash-cpu'), nextCpu, [
					[ _('Used'), '%d%%'.format(nextCpu), 'bullet' ],
					[ _('Idle'), '%d%%'.format(100 - nextCpu), 'bullet light' ]
				]);
				updateDonut(document.getElementById('airdash-memory'), nextMemPct, [
					[ _('Used'), fmtBytes(nextUsed), 'bullet navy' ],
					[ _('Free'), fmtBytes(nextFree), 'bullet light' ]
				]);
			});
		}, 3);

		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
