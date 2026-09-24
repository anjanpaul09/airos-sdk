'use strict';
'require view';
'require dom';
'require poll';
'require rpc';
'require network';

var callRealtimeStats = rpc.declare({
	object: 'luci',
	method: 'getRealtimeStats',
	params: [ 'mode', 'device' ],
	expect: { result: [] }
});

var callSystemInfo = rpc.declare({
	object: 'system',
	method: 'info'
});

var pollInterval = 3;
var maxPoints = 96;

function fmtBytes(v) {
	return '%1024.2mB'.format(v || 0);
}

function fmtRate(v) {
	return '%1024.2mbit/s'.format((v || 0) * 8);
}

function last(rows) {
	return rows && rows.length ? rows[rows.length - 1] : null;
}

function pushPoint(series, value) {
	series.push(isNaN(value) ? 0 : value);

	if (series.length > maxPoints)
		series.splice(0, series.length - maxPoints);
}

function drawChart(canvas, series, colors, labels, unit) {
	var ctx = canvas.getContext('2d');
	var rect = canvas.getBoundingClientRect();
	var dpr = window.devicePixelRatio || 1;
	var width = Math.max(320, Math.floor(rect.width));
	var height = 220;
	var pad = 28;
	var max = 1;

	if (canvas.width != width * dpr || canvas.height != height * dpr) {
		canvas.width = width * dpr;
		canvas.height = height * dpr;
		canvas.style.height = height + 'px';
		ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
	}

	for (var i = 0; i < series.length; i++)
		for (var j = 0; j < series[i].length; j++)
			max = Math.max(max, series[i][j]);

	max *= 1.15;

	ctx.clearRect(0, 0, width, height);
	ctx.fillStyle = '#ffffff';
	ctx.fillRect(0, 0, width, height);

	ctx.strokeStyle = '#dce3ee';
	ctx.lineWidth = 1;

	for (var g = 0; g < 4; g++) {
		var y = pad + ((height - pad * 2) / 3) * g;
		ctx.beginPath();
		ctx.moveTo(pad, y);
		ctx.lineTo(width - pad, y);
		ctx.stroke();
	}

	ctx.fillStyle = '#687386';
	ctx.font = '12px sans-serif';
	ctx.fillText(unit(max), pad, 16);
	ctx.fillText(unit(0), pad, height - 8);

	for (var s = 0; s < series.length; s++) {
		ctx.strokeStyle = colors[s];
		ctx.lineWidth = 2;
		ctx.beginPath();

		for (var p = 0; p < series[s].length; p++) {
			var x = pad + (width - pad * 2) * (p / Math.max(1, maxPoints - 1));
			var y = height - pad - ((height - pad * 2) * (series[s][p] / max));

			if (p == 0)
				ctx.moveTo(x, y);
			else
				ctx.lineTo(x, y);
		}

		ctx.stroke();
	}

	for (var l = 0; l < labels.length; l++) {
		ctx.fillStyle = colors[l];
		ctx.fillRect(width - 154, 14 + l * 18, 10, 10);
		ctx.fillStyle = '#172033';
		ctx.fillText(labels[l], width - 138, 23 + l * 18);
	}
}

function card(title, value, note, id) {
	return E('div', { 'class': 'telemetry-card' }, [
		E('span', { 'class': 'telemetry-label' }, title),
		E('strong', { 'id': id }, value),
		E('small', {}, note || '-')
	]);
}

function chart(title, note, id) {
	return E('div', { 'class': 'telemetry-chart' }, [
		E('div', { 'class': 'telemetry-chart-head' }, [
			E('div', {}, [
				E('h3', {}, title),
				E('small', {}, note)
			])
		]),
		E('canvas', { 'id': id })
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			network.getDevices(),
			L.resolveDefault(callSystemInfo(), {})
		]);
	},

	render: function(data) {
		var devices = data[0].filter(function(dev) {
			var name = dev.getName();
			return name && name != 'lo';
		});

		var state = {
			load: [ [], [], [] ],
			devices: {},
			lastTraffic: {},
			deviceNames: devices.map(function(dev) { return dev.getName(); })
		};

		var deviceCharts = [];

		for (var i = 0; i < devices.length; i++) {
			var ifname = devices[i].getName();
			state.devices[ifname] = [ [], [] ];
			deviceCharts.push(chart(ifname + ' traffic', _('Inbound and outbound throughput'), 'chart-iface-' + ifname.replace(/[^A-Za-z0-9_-]/g, '_')));
		}

		var viewNode = E('div', { 'class': 'cbi-map telemetry-page' }, [
			E('h2', {}, _('Graph Telemetrics')),
			E('div', { 'class': 'cbi-map-descr' }, _('Live AP telemetry collected from LuCI realtime statistics.')),
			E('div', { 'class': 'telemetry-cards' }, [
				card(_('Load 1m'), '0.00', _('Current'), 'tm-load-1'),
				card(_('Load 5m'), '0.00', _('Current'), 'tm-load-5'),
				card(_('Memory Used'), '-', _('RAM'), 'tm-memory'),
				card(_('Interfaces'), String(devices.length), _('Active devices'), 'tm-ifaces')
			]),
			E('div', { 'class': 'telemetry-grid' }, [
				chart(_('System load'), _('1, 5 and 15 minute load averages'), 'chart-load')
			].concat(deviceCharts))
		]);

		poll.add(function() {
			var tasks = [
				L.resolveDefault(callRealtimeStats('load'), []),
				L.resolveDefault(callSystemInfo(), {})
			];

			for (var i = 0; i < state.deviceNames.length; i++)
				tasks.push(L.resolveDefault(callRealtimeStats('interface', state.deviceNames[i]), []));

			return Promise.all(tasks).then(function(results) {
				var loadRows = results[0];
				var systemInfo = results[1] || {};
				var loadRow = last(loadRows);
				var mem = L.isObject(systemInfo.memory) ? systemInfo.memory : {};

				if (loadRow) {
					pushPoint(state.load[0], (loadRow[1] || 0) / 100);
					pushPoint(state.load[1], (loadRow[2] || 0) / 100);
					pushPoint(state.load[2], (loadRow[3] || 0) / 100);

					document.getElementById('tm-load-1').textContent = '%.2f'.format((loadRow[1] || 0) / 100);
					document.getElementById('tm-load-5').textContent = '%.2f'.format((loadRow[2] || 0) / 100);
				}

				if (mem.total && mem.free) {
					var used = mem.total - mem.free;
					document.getElementById('tm-memory').textContent = '%s / %s'.format(fmtBytes(used), fmtBytes(mem.total));
				}

				drawChart(document.getElementById('chart-load'), state.load,
					[ '#1457d9', '#1f7a8c', '#f59e0b' ],
					[ '1m', '5m', '15m' ],
					function(v) { return '%.2f'.format(v); });

				for (var i = 0; i < state.deviceNames.length; i++) {
					var ifname = state.deviceNames[i];
					var rows = results[i + 2];
					var row = last(rows);
					var prev = state.lastTraffic[ifname];
					var rx = 0;
					var tx = 0;

					if (row && prev && row[0] > prev[0]) {
						var delta = row[0] - prev[0];
						rx = Math.max(0, ((row[1] || 0) - (prev[1] || 0)) / delta);
						tx = Math.max(0, ((row[3] || 0) - (prev[3] || 0)) / delta);
					}

					if (row)
						state.lastTraffic[ifname] = row;

					pushPoint(state.devices[ifname][0], rx);
					pushPoint(state.devices[ifname][1], tx);

					drawChart(document.getElementById('chart-iface-' + ifname.replace(/[^A-Za-z0-9_-]/g, '_')),
						state.devices[ifname],
						[ '#1457d9', '#1f7a8c' ],
						[ 'RX', 'TX' ],
						fmtRate);
				}
			});
		}, pollInterval);

		return viewNode;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
