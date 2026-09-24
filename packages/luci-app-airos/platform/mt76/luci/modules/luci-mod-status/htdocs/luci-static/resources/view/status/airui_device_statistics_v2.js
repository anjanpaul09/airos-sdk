'use strict';
'require view';
'require poll';
'require rpc';

var callStatusStatistics = rpc.declare({ object: 'airui.status', method: 'statistics', expect: { '': {} } });

var pollInterval = 3;
var maxPoints = 72;

function cleanId(name) {
	return String(name || 'iface').replace(/[^A-Za-z0-9_-]/g, '_');
}

function fmtBytes(v) {
	return '%1024.1mB'.format(Math.max(0, v || 0));
}

function fmtRate(v) {
	return '%1024.2mB/s'.format(Math.max(0, v || 0));
}

function fmtLoad(v) {
	return '%.2f'.format(v || 0);
}

function last(rows) {
	return rows && rows.length ? rows[rows.length - 1] : null;
}

function envelopeData(response) {
	return response && response.ok !== false && response.data ? response.data : {};
}

function parseProcNetDev(text) {
	var rows = {};
	var lines = (text || '').split(/\n/);

	for (var i = 0; i < lines.length; i++) {
		var m = lines[i].match(/^\s*([^:]+):\s*(.*)$/);

		if (!m)
			continue;

		var name = m[1].trim();
		var p = m[2].trim().split(/\s+/).map(function(v) { return +v || 0; });

		if (!name || name == 'lo')
			continue;

		rows[name] = {
			time: Date.now() / 1000,
			rx: p[0] || 0,
			rxErrors: p[2] || 0,
			rxDrops: p[3] || 0,
			tx: p[8] || 0,
			txErrors: p[10] || 0,
			txDrops: p[11] || 0
		};
	}

	return rows;
}

function pushPoint(series, value) {
	series.push(isNaN(value) ? 0 : value);

	if (series.length > maxPoints)
		series.splice(0, series.length - maxPoints);
}

function drawChart(canvas, series, colors, labels, unit) {
	if (!canvas)
		return;

	var ctx = canvas.getContext('2d');
	var rect = canvas.getBoundingClientRect();
	var dpr = window.devicePixelRatio || 1;
	var width = Math.max(360, Math.floor(rect.width));
	var height = 250;
	var padLeft = 44;
	var padRight = 22;
	var padTop = 30;
	var padBottom = 34;
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

	max *= 1.18;

	ctx.clearRect(0, 0, width, height);
	ctx.fillStyle = '#ffffff';
	ctx.fillRect(0, 0, width, height);

	ctx.strokeStyle = '#ead8cc';
	ctx.lineWidth = 1;
	ctx.fillStyle = '#848688';
	ctx.font = '11px Inter, Segoe UI, Arial, sans-serif';

	for (var g = 0; g < 4; g++) {
		var y = padTop + ((height - padTop - padBottom) / 3) * g;
		ctx.beginPath();
		ctx.moveTo(padLeft, y);
		ctx.lineTo(width - padRight, y);
		ctx.stroke();
	}

	ctx.fillText(unit(max), 8, padTop + 4);
	ctx.fillText(unit(0), 8, height - padBottom + 4);

	for (var s = 0; s < series.length; s++) {
		ctx.strokeStyle = colors[s];
		ctx.lineWidth = 2.5;
		ctx.beginPath();

		for (var p = 0; p < series[s].length; p++) {
			var x = padLeft + (width - padLeft - padRight) * (p / Math.max(1, maxPoints - 1));
			var y2 = height - padBottom - ((height - padTop - padBottom) * (series[s][p] / max));

			if (p == 0)
				ctx.moveTo(x, y2);
			else
				ctx.lineTo(x, y2);
		}

		ctx.stroke();
	}

	for (var l = 0; l < labels.length; l++) {
		var lx = width - 136 + l * 62;
		ctx.fillStyle = colors[l];
		ctx.fillRect(lx, 14, 9, 9);
		ctx.fillStyle = '#17084d';
		ctx.fillText(labels[l], lx + 14, 23);
	}
}

function hero() {
	return E('section', { 'class': 'stats-hero' }, [
		E('div', {}, [
			E('span', { 'class': 'eyebrow' }, _('Device Statistics')),
			E('h1', {}, _('Traffic & Radio Metrics')),
			E('p', {}, _('Live throughput, interface counters, load trend, and wireless retry health from the device telemetry backend.'))
		]),
		E('button', {
			'class': 'clients-refresh',
			'type': 'button',
			'click': function() { window.location.reload(); }
		}, _('Refresh'))
	]);
}

function stat(label, value, note, id, active) {
	return E('article', { 'class': active ? 'client-stat is-active' : 'client-stat' }, [
		E('span', { 'class': 'client-stat-dot' }),
		E('small', {}, label),
		E('strong', { 'class': 'tech', 'id': id }, value),
		E('em', {}, note || '')
	]);
}

function chartPanel(title, note, id) {
	return E('section', { 'class': 'stats-panel' }, [
		E('div', { 'class': 'stats-panel-head' }, [
			E('div', {}, [
				E('h2', {}, title),
				E('p', {}, note)
			])
		]),
		E('canvas', { 'id': id })
	]);
}

function ifaceRow(ifname) {
	var id = cleanId(ifname);

	return E('div', { 'class': 'stats-iface-row', 'id': 'stats-iface-' + id }, [
		E('span', { 'class': 'tech' }, ifname),
		E('span', { 'class': 'tech stat-rx-rate' }, '-'),
		E('span', { 'class': 'tech stat-tx-rate' }, '-'),
		E('span', { 'class': 'tech stat-rx-total' }, '-'),
		E('span', { 'class': 'tech stat-tx-total' }, '-'),
		E('span', { 'class': 'stat-health' }, _('No packet errors'))
	]);
}

return view.extend({
	load: function() {
		return L.resolveDefault(callStatusStatistics(), {});
	},

	render: function(data) {
		var payload = envelopeData(data);
		var counters = parseProcNetDev(payload.proc_net_dev);
		var deviceNames = Object.keys(counters);

		var state = {
			load: [ [], [], [] ],
			deviceNames: deviceNames,
			devices: {},
			lastTraffic: {}
		};

		for (var i = 0; i < state.deviceNames.length; i++)
			state.devices[state.deviceNames[i]] = [ [], [] ];

		var primary = state.deviceNames.indexOf('br-lan') >= 0 ? 'br-lan' : state.deviceNames[0];

		var page = E('div', { 'class': 'airdash clients-page stats-page' }, [
			hero(),
			E('section', { 'class': 'client-stats stats-summary' }, [
				stat(_('Download'), '-', _('aggregate RX rate'), 'stats-download', true),
				stat(_('Upload'), '-', _('aggregate TX rate'), 'stats-upload', false),
				stat(_('Load'), '-', _('1 minute average'), 'stats-load', false),
				stat(_('Interfaces'), String(state.deviceNames.length), _('reporting counters'), 'stats-ifaces', false)
			]),
			E('section', { 'class': 'stats-grid' }, [
				chartPanel(_('Live Traffic'), _('RX and TX throughput over the last few minutes.'), 'stats-chart-traffic'),
				chartPanel(_('System Load'), _('1, 5, and 15 minute load averages.'), 'stats-chart-load')
			]),
			E('section', { 'class': 'client-panel stats-interface-panel' }, [
				E('div', { 'class': 'client-panel-head' }, [
					E('h2', {}, _('Interface Counters')),
					E('span', { 'class': 'tech' }, String(state.deviceNames.length))
				]),
				E('div', { 'class': 'stats-iface-table' }, [
					E('div', { 'class': 'stats-iface-head' }, [
						E('span', {}, _('Interface')),
						E('span', {}, _('RX Rate')),
						E('span', {}, _('TX Rate')),
						E('span', {}, _('RX Total')),
						E('span', {}, _('TX Total')),
						E('span', {}, _('Health'))
					]),
					E('div', { 'class': 'stats-iface-body' }, state.deviceNames.length ?
						state.deviceNames.map(ifaceRow) :
						[ E('div', { 'class': 'client-empty' }, _('No interfaces are reporting counters.')) ])
				])
			])
		]);

		poll.add(function() {
			return L.resolveDefault(callStatusStatistics(), {}).then(function(result) {
				var nextPayload = envelopeData(result);
				var nextCounters = parseProcNetDev(nextPayload.proc_net_dev);
				var loadValues = nextPayload.system && nextPayload.system.load || [];
				var download = 0;
				var upload = 0;

				if (loadValues.length) {
					var load1 = (loadValues[0] || 0) / 65536;
					var load5 = (loadValues[1] || 0) / 65536;
					var load15 = (loadValues[2] || 0) / 65536;

					pushPoint(state.load[0], load1);
					pushPoint(state.load[1], load5);
					pushPoint(state.load[2], load15);

					var loadEl = document.getElementById('stats-load');
					if (loadEl)
						loadEl.textContent = fmtLoad(load1);
				}

				for (var i = 0; i < state.deviceNames.length; i++) {
					var ifname = state.deviceNames[i];
					var row = nextCounters[ifname];
					var prev = state.lastTraffic[ifname];
					var rx = 0;
					var tx = 0;

					if (row && prev && row.time > prev.time) {
						var delta = row.time - prev.time;
						rx = Math.max(0, ((row.rx || 0) - (prev.rx || 0)) / delta);
						tx = Math.max(0, ((row.tx || 0) - (prev.tx || 0)) / delta);
					}

					if (row)
						state.lastTraffic[ifname] = row;

					pushPoint(state.devices[ifname][0], rx);
					pushPoint(state.devices[ifname][1], tx);

					download += rx;
					upload += tx;

					var rowNode = document.getElementById('stats-iface-' + cleanId(ifname));
					if (rowNode && row) {
						rowNode.querySelector('.stat-rx-rate').textContent = fmtRate(rx);
						rowNode.querySelector('.stat-tx-rate').textContent = fmtRate(tx);
						rowNode.querySelector('.stat-rx-total').textContent = fmtBytes(row.rx || 0);
						rowNode.querySelector('.stat-tx-total').textContent = fmtBytes(row.tx || 0);
					}
				}

				var downEl = document.getElementById('stats-download');
				var upEl = document.getElementById('stats-upload');

				if (downEl)
					downEl.textContent = fmtRate(download);
				if (upEl)
					upEl.textContent = fmtRate(upload);

				drawChart(document.getElementById('stats-chart-load'), state.load,
					[ '#17084d', '#f58634', '#848688' ],
					[ '1m', '5m', '15m' ],
					fmtLoad);

				drawChart(document.getElementById('stats-chart-traffic'),
					primary ? state.devices[primary] : [ [], [] ],
					[ '#17084d', '#f58634' ],
					[ 'RX', 'TX' ],
					fmtRate);
			});
		}, pollInterval);

		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
