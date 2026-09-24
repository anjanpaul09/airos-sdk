'use strict';
'require view';
'require ui';
'require rpc';
'require dom';

var SERVICES = [
	{ key: 'https', label: 'HTTPS', port: '443', proto: 'tcp', hint: 'Secure web management.' },
	{ key: 'http', label: 'HTTP', port: '80', proto: 'tcp', hint: 'Web management and HTTPS redirection.' },
	{ key: 'ssh', label: 'SSH', port: '3041', proto: 'tcp', hint: 'Command-line management access.' },
	{ key: 'snmp', label: 'SNMP', port: '161', proto: 'udp', hint: 'Network monitoring access.' }
];
var callGet = rpc.declare({ object: 'airui.security', method: 'access_control_get', expect: { '': {} } });
var callSet = rpc.declare({
	object: 'airui.security', method: 'access_control_set',
	params: [ 'https', 'http', 'ssh', 'snmp', 'remote_wan', 'lan_subnet' ],
	expect: { '': {} }
});

function responseData(r) { return r && r.data ? r.data : {}; }
function responseError(r, fallback) { return r && r.errors && r.errors[0] ? r.errors[0].message || fallback : fallback; }

return view.extend({
	busy: false,
	state: {},
	root: null,

	load: function() { return callGet(); },
	serviceEnabled: function(key) {
		return this.state[key] === true;
	},
	refresh: function() {
		if (this.busy) return Promise.resolve();
		this.busy = true;
		return callGet().then(L.bind(function(r) {
			if (!r || r.ok === false) throw new Error(responseError(r, _('Unable to load access controls')));
			this.state = responseData(r);
			dom.content(this.root, this.renderPage());
		}, this)).catch(function(e) { ui.addNotification(null, E('p', {}, e.message), 'error'); })
			.finally(L.bind(function() { this.busy = false; }, this));
	},
	serviceToggle: function(service) {
		var enabled = this.serviceEnabled(service.key);
		var unavailable = service.key === 'snmp' && this.state.snmp_available === false;
		var input = E('input', {
			'type': 'checkbox', 'name': service.key,
			'checked': enabled ? 'checked' : null,
			'disabled': unavailable ? 'disabled' : null,
			'aria-label': _('Enable %s').format(service.label)
		});
		var control = E('div', { 'class': enabled ? 'air-setting-toggle is-on' : 'air-setting-toggle' }, [
			E('span', { 'class': 'air-setting-copy' }, [
				E('strong', {}, service.label),
				E('small', {}, unavailable ? _('Not installed on this device.') : _(service.hint))
			]),
			E('label', { 'class': 'air-toggle-switch' }, [ input, E('span', { 'aria-hidden': 'true' }) ])
		]);
		input.addEventListener('change', function(ev) {
			control.classList.toggle('is-on', ev.target.checked);
		});
		return control;
	},
	save: function(button, apply, ev) {
		if (ev && ev.preventDefault)
			ev.preventDefault();

		if (this.busy) return;
		var remoteWan = this.root.querySelector('[name="remote_wan"]').checked;
		var subnet = this.root.querySelector('[name="lan_subnet"]').value.trim();
		if (subnet && !/^([0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(subnet)) {
			ui.addNotification(null, E('p', {}, _('Enter a valid IPv4 subnet, for example 192.168.1.0/24.')), 'error');
			return;
		}
		var values = {};
		SERVICES.forEach(L.bind(function(service) {
			values[service.key] = this.root.querySelector('[name="' + service.key + '"]').checked;
		}, this));
		if (!values.http && !values.https) {
			ui.addNotification(null, E('p', {}, _('Keep HTTP or HTTPS enabled to preserve web management access.')), 'error');
			return;
		}
		this.busy = true;
		button.disabled = true;
		button.textContent = _('Applying...');
		callSet(values.https, values.http, values.ssh, values.snmp, remoteWan, subnet).then(L.bind(function(result) {
			if (!result || result.ok === false) throw new Error(responseError(result, _('Unable to apply access controls')));
			this.state = responseData(result);
			ui.addNotification(null, E('p', {}, apply ? _('Access controls applied.') : _('Access controls saved.')), 'info');
			this.busy = false;
			return this.refresh();
		}, this)).catch(function(e) { ui.addNotification(null, E('p', {}, e.message), 'error'); })
			.finally(L.bind(function() { this.busy = false; button.disabled = false; button.textContent = apply ? _('Save & Apply') : _('Save'); }, this));
	},
	renderPage: function() {
		var remoteInput = E('input', {
			'name': 'remote_wan', 'type': 'checkbox',
			'checked': this.state.remote_wan ? 'checked' : null,
			'aria-label': _('Enable remote WAN access')
		});
		var remoteControl = E('div', { 'class': this.state.remote_wan ? 'air-setting-toggle is-on' : 'air-setting-toggle' }, [
			E('span', { 'class': 'air-setting-copy' }, [
				E('strong', {}, _('Remote WAN access')),
				E('small', {}, _('Allow enabled management services from WAN.'))
			]),
			E('label', { 'class': 'air-toggle-switch' }, [ remoteInput, E('span', { 'aria-hidden': 'true' }) ])
		]);
		remoteInput.addEventListener('change', function(ev) {
			remoteControl.classList.toggle('is-on', ev.target.checked);
		});
		return E('div', { 'class': 'air-page air-settings-page ac-simple-page' }, [
			E('section', { 'class': 'air-settings-hero' }, [ E('div', {}, [ E('span', { 'class': 'air-settings-kicker' }, _('Security')), E('h1', {}, _('Access Control')), E('p', {}, _('Choose which management services can reach this access point.')) ]) ]),
				E('section', { 'class': 'air-settings-summary' }, [
					[ _('HTTPS'), this.serviceEnabled('https') ? _('Enabled') : _('Disabled') ], [ _('SSH'), this.serviceEnabled('ssh') ? _('Enabled') : _('Disabled') ],
					[ _('Remote WAN'), this.state.remote_wan ? _('Enabled') : _('Disabled') ], [ _('Allowed source'), this.state.remote_wan ? _('WAN') : (this.state.lan_subnet || _('LAN')) ]
			].map(function(item) {
				var positive = item[1] == _('Enabled');
				var statusValue = item[1] == _('Enabled') || item[1] == _('Disabled');
				return E('div', { 'class': 'air-setting-item' }, [
					E('span', {}, item[0]),
					statusValue ? E('strong', { 'class': positive ? 'air-status-pill is-positive' : 'air-status-pill is-disabled' }, item[1]) : E('strong', {}, item[1])
				]);
			})),
			E('div', { 'class': 'air-settings-grid' }, [
				E('section', { 'class': 'air-card air-settings-card' }, [ E('div', { 'class': 'air-card-head' }, E('h3', {}, _('Management Services'))), E('div', { 'class': 'air-settings-toggle-grid' }, SERVICES.map(L.bind(this.serviceToggle, this))) ]),
					E('section', { 'class': 'air-card air-settings-card' }, [ E('div', { 'class': 'air-card-head' }, E('h3', {}, _('Allowed Sources'))), E('div', { 'class': 'air-settings-form' }, [
						E('label', { 'class': 'air-setting-field' }, [ E('span', {}, _('LAN subnet')), E('input', { 'name': 'lan_subnet', 'type': 'text', 'value': this.state.lan_subnet || '192.168.1.0/24', 'placeholder': '192.168.1.0/24' }) ]),
						remoteControl
				]) ])
			]),
			E('section', { 'class': 'air-settings-applybar' }, [
				E('div', {}, [ E('span', {}, '!'), E('strong', {}, _('Access changes reload the firewall and may interrupt management connections.')) ]),
				E('div', { 'class': 'air-standard-actions' }, [
					E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
					E('button', {
						'class': 'air-action',
						'type': 'button',
						'click': L.bind(function(ev) { this.save(ev.currentTarget, false, ev); }, this)
					}, _('Save')),
					E('button', {
						'class': 'air-action is-primary',
						'type': 'button',
						'click': L.bind(function(ev) { this.save(ev.currentTarget, true, ev); }, this)
					}, _('Save & Apply'))
				])
			])
		]);
	},
	render: function(r) {
		if (!r || r.ok === false) return E('div', { 'class': 'alert-message error' }, responseError(r, _('Unable to load access controls')));
		this.state = responseData(r);
		this.root = E('div', {}, this.renderPage());
		return this.root;
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
