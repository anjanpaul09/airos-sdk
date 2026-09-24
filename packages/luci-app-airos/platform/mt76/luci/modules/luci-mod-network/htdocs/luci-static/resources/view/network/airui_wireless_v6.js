'use strict';
'require view';
'require rpc';
'require ui';
'require airui.apply_status_v2 as applyStatus';

var callHealth = rpc.declare({
	object: 'airui.system',
	method: 'health',
	expect: { '': {} }
});

var callCapabilities = rpc.declare({
	object: 'airui.system',
	method: 'capabilities',
	expect: { '': {} }
});

var callWirelessConfig = rpc.declare({
	object: 'airui.network',
	method: 'wireless_config',
	expect: { '': {} }
});

var callInterfaceConfig = rpc.declare({
	object: 'airui.network',
	method: 'interface_config',
	expect: { '': {} }
});

var callWirelessSet = rpc.declare({
	object: 'airui.network',
	method: 'wireless_set',
	params: [
		'section',
		'type',
		'device',
		'mode',
		'disabled',
		'ssid',
		'encryption',
		'key',
		'network',
		'channel',
		'htmode',
		'country',
		'hidden',
		'isolate',
		'maxassoc',
		'band_steering',
		'airtime_fairness',
		'download',
		'upload',
		'air_vif_id',
		'air_link_id',
		'air_mld_id',
		'mld_id',
		'security_ref',
		'network_ref',
		'qos_ref',
		'portal_ref',
		'dry_run'
	],
	expect: { '': {} }
});

var callWirelessAdd = rpc.declare({
	object: 'airui.network',
	method: 'wireless_add',
	params: [
		'section',
		'type',
		'device',
		'mode',
		'network',
		'ssid',
		'encryption',
		'key',
		'disabled',
		'dry_run'
	],
	expect: { '': {} }
});

var callWirelessDelete = rpc.declare({
	object: 'airui.network',
	method: 'wireless_delete',
	params: [ 'section', 'dry_run' ],
	expect: { '': {} }
});

var RADIO_SECTIONS = [
	{ section: 'wlan1', device: 'wifi1', bandKey: '2g', bandLabel: '2.4 GHz' },
	{ section: 'wlan2', device: 'wifi0', bandKey: '5g', bandLabel: '5 GHz' }
];

var lastConfig = null;
var lastInterfaceConfig = null;

function text(value, fallback) {
	if (value === null || value === undefined || value === '')
		return fallback || '-';

	return String(value);
}

function generatedVifId() {
	var seed = '%s:%s'.format(Date.now(), Math.floor(Math.random() * 0xffffff));
	var hash = 2166136261;

	for (var i = 0; i < seed.length; i++) {
		hash ^= seed.charCodeAt(i);
		hash = Math.imul(hash, 16777619);
	}

	return 'vif_%s'.format((hash >>> 0).toString(16).slice(-6).padStart(6, '0'));
}

function backendError(env, fallback) {
	if (env && Array.isArray(env.errors) && env.errors[0])
		return env.errors[0].message || env.errors[0].code || fallback;

	return fallback;
}

function featureNotReady(err) {
	var msg = err && (err.message || err.toString && err.toString()) || '';
	return {
		ok: false,
		feature_not_ready: true,
		data: {},
		warnings: [],
		errors: [ { message: msg || _('Backend method is not available yet.') } ],
		meta: {}
	};
}

function safeCall(fn) {
	return Promise.resolve().then(fn).catch(featureNotReady);
}

function valuesFromEnvelope(env) {
	return env && env.ok !== false && env.data && env.data.uci && env.data.uci.values
		? env.data.uci.values
		: {};
}

function runtimeFromEnvelope(env) {
	return env && env.ok !== false && env.data && env.data.runtime
		? env.data.runtime
		: {};
}

function enterpriseFromEnvelope(env) {
	return env && env.ok !== false && env.data && env.data.enterprise
		? env.data.enterprise
		: {};
}

function interfaceValuesFromEnvelope(env) {
	if (!env || env.ok === false || !env.data || !env.data.uci)
		return {};

	if (env.data.uci.network && env.data.uci.network.values)
		return env.data.uci.network.values;

	if (env.data.uci.values)
		return env.data.uci.values;

	return {};
}

function sectionConfig(values, section) {
	return values[section] || {};
}

function radioConfig(values, info) {
	return values[info.device] || {};
}

function deviceBand(device) {
	return device == 'wifi1' ? '2.4 GHz' : '5 GHz';
}

function bandLabelFromKey(band) {
	if (band == '2g')
		return _('2.4 GHz');

	if (band == '5g')
		return _('5 GHz');

	if (band == '6g')
		return _('6 GHz');

	return text(band, _('Unknown'));
}

function infoForIface(section, cfg) {
	var device = text(cfg.device, section == 'wlan1' ? 'wifi1' : 'wifi0');
	return {
		section: section,
		device: device,
		bandKey: device == 'wifi1' ? '2g' : '5g',
		bandLabel: deviceBand(device)
	};
}

function ifaceSections(values) {
	var sections = [];
	var seen = {};
	var activeOrder = { wlan1: 0, wlan2: 1 };

	Object.keys(activeOrder).forEach(function(section) {
		if (values[section] && values[section]['.type'] == 'wifi-iface') {
			sections.push(section);
			seen[section] = true;
		}
	});

	Object.keys(values || {}).sort().forEach(function(section) {
		if (seen[section])
			return;

		if (values[section] && values[section]['.type'] == 'wifi-iface') {
			sections.push(section);
			seen[section] = true;
		}
	});

	return sections;
}

function radioRuntime(runtime, info) {
	return runtime[info.device] || runtime[info.bandKey] || {};
}

function radioRuntimeConfig(runtime, info) {
	var radio = radioRuntime(runtime, info);
	return radio.config || radio;
}

function interfaceRuntime(runtime, info) {
	var radio = radioRuntime(runtime, info);
	var ifaces = Array.isArray(radio.interfaces) ? radio.interfaces : [];

	for (var i = 0; i < ifaces.length; i++) {
		if (ifaces[i] && ifaces[i].section == info.section)
			return ifaces[i];
	}

	return runtime[info.section] || {};
}

function interfaceRuntimeConfig(runtime, info) {
	var iface = interfaceRuntime(runtime, info);
	return iface.config || iface;
}

function isDisabled(cfg, runtime) {
	if (typeof cfg.disabled == 'boolean')
		return cfg.disabled;

	if (String(cfg.disabled) == '1' || String(cfg.disabled).toLowerCase() == 'true')
		return true;

	if (typeof runtime.disabled == 'boolean')
		return runtime.disabled;

	return false;
}

function clientCount(runtime) {
	if (typeof runtime.clients == 'number')
		return runtime.clients;

	if (Array.isArray(runtime.clients))
		return runtime.clients.length;

	if (Array.isArray(runtime.assoclist))
		return runtime.assoclist.length;

	if (Array.isArray(runtime.stations))
		return runtime.stations.length;

	if (Array.isArray(runtime.interfaces)) {
		var total = 0;

		for (var i = 0; i < runtime.interfaces.length; i++)
			total += clientCount(runtime.interfaces[i] || {});

		return total;
	}

	return 0;
}

function option(value, label, current) {
	return E('option', {
		'value': value,
		'selected': String(current) == String(value) ? 'selected' : null
	}, label);
}

function isBand24(band) {
	return String(band || '').indexOf('2.4') >= 0 || String(band || '') == '2g';
}

function defaultMode(band) {
	return isBand24(band) ? '802.11b/g/n' : '802.11a/n/ac/ax/be';
}

function channelOptions(current, band) {
	var value = text(current, 'auto');
	var channels = isBand24(band) ? [ '1', '6', '11' ] : [ '36', '44', '149', '157' ];
	var opts = [ option('auto', _('Auto'), value) ];

	for (var i = 0; i < channels.length; i++)
		opts.push(option(channels[i], channels[i], value));

	return opts;
}

function widthOptions(current, band) {
	var value = text(current, isBand24(band) ? 'HE40' : 'HE80');
	var opts = [
		option('', _('Auto'), value),
		option('HT20', '20 MHz', value),
		option('HE20', '20 MHz', value),
		option('HE40', isBand24(band) ? '20/40 MHz' : '40 MHz', value)
	];

	if (!isBand24(band)) {
		opts.push(option('VHT80', '80 MHz (Wi-Fi 5)', value));
		opts.push(option('HE80', '80 MHz (Wi-Fi 6)', value));
		opts.push(option('EHT80', '80 MHz (Wi-Fi 7)', value));
	}

	return opts;
}

function txPowerOptions(current, band) {
	var configured = parseInt(current, 10);
	var level = configured <= 17 ? 'low' : (configured <= 22 ? 'medium' : 'high');
	var highValue = configured > 22 ? String(configured) : (isBand24(band) ? '25' : '30');

	if (!configured) {
		level = 'high';
		configured = parseInt(highValue, 10);
	}

	return [
		option('14', _('Low'), level == 'low' ? '14' : ''),
		option('20', _('Medium'), level == 'medium' ? '20' : ''),
		option(highValue, _('High'), level == 'high' ? highValue : '')
	];
}

function modeOptions(current, band) {
	var value = text(current, defaultMode(band));

	if (isBand24(band)) {
		return [
			option('802.11b/g', '802.11b/g', value),
			option('802.11b/g/n', '802.11b/g/n', value)
		];
	}

	return [
		option('802.11a/n', '802.11a/n', value),
		option('802.11a/n/ac', '802.11a/n/ac', value),
		option('802.11a/n/ac/ax', '802.11a/n/ac/ax', value),
		option('802.11a/n/ac/ax/be', '802.11a/n/ac/ax/be', value)
	];
}

function networkOptions(current) {
	var value = text(current, 'lan');
	var names = interfaceNetworkNames(lastInterfaceConfig, value);

	return names.map(function(name) {
		return option(name, name, value);
	});
}

function networkLabel(name) {
	if (name == 'lan')
		return _('LAN');

	if (name == 'wan')
		return _('WAN');

	if (name == 'guest')
		return _('Guest');

	if (name == 'nat_network')
		return _('NAT Network');

	return name;
}

function interfaceNetworkNames(env, current) {
	var values = interfaceValuesFromEnvelope(env);
	var names = [];
	var seen = {};

	function push(name) {
		name = text(name, '').trim();

		if (!name || name == 'loopback' || /_dev$/i.test(name) || seen[name])
			return;

		seen[name] = true;
		names.push(name);
	}

	Object.keys(values || {}).sort().forEach(function(name) {
		var cfg = values[name] || {};

		if (cfg['.type'] == 'interface')
			push(name);
	});

	[ 'lan', 'wan', 'guest', 'nat_network' ].forEach(push);
	push(current);

	return names;
}

function encryptionOptions(current) {
	var value = text(current, 'none');
	return [
		option('none', _('Open'), value),
		option('psk2', _('WPA2-Personal'), value),
		option('sae', _('WPA3-Personal'), value),
		option('psk2+sae', _('WPA2/WPA3-Personal'), value)
	];
}

function limitOptions(current, fallback) {
	var value = current || fallback;
	return [
		option('', _('Unlimited'), value),
		option('10', '10 Mbps', value),
		option('25', '25 Mbps', value),
		option('50', '50 Mbps', value),
		option('100', '100 Mbps', value)
	];
}

function encryptionLabel(mode) {
	mode = text(mode, 'none');

	if (mode == 'none')
		return _('Open');

	if (mode == 'psk2')
		return _('WPA2');

	if (mode == 'sae')
		return _('WPA3');

	if (mode == 'psk2+sae' || mode == 'sae-mixed')
		return _('WPA2/WPA3');

	return mode;
}

function pill(enabled) {
	return E('span', { 'class': enabled ? 'wireless-status-pill is-on' : 'wireless-status-pill' },
		enabled ? _('Active') : _('Disabled'));
}

function miniIcon(kind) {
	return E('span', { 'class': 'wireless-mini-icon wireless-mini-icon-' + (kind || 'wifi'), 'aria-hidden': 'true' });
}

function bandChips(bands, fallback) {
	var values = Array.isArray(bands) && bands.length ? bands : [ fallback ];

	return E('div', { 'class': 'wireless-band-chips' }, values.map(function(band) {
		return E('span', { 'class': 'wireless-band-chip' }, bandLabelFromKey(band));
	}));
}

function ssidSignal(enabled) {
	return E('span', { 'class': enabled ? 'wireless-ssid-dot is-on' : 'wireless-ssid-dot', 'aria-hidden': 'true' });
}

function iconButton(kind, className, title, onClick) {
	return E('button', {
		'class': (className || 'wireless-ref-icon-button') + ' wireless-icon-' + kind,
		'type': 'button',
		'title': title,
		'aria-label': title,
		'click': onClick
	});
}

function toggleSsidCard(source) {
	var target = source && source.target ? source.target : source;
	var card = target && target.closest ? target.closest('.wireless-ref-ssid') : null;
	var open = card && !card.classList.contains('is-open');
	var button = card ? card.querySelector('.wireless-icon-chevronUp, .wireless-icon-chevronDown') : null;

	document.querySelectorAll('.wireless-ref-ssid').forEach(function(item) {
		var toggle = item.querySelector('.wireless-icon-chevronUp, .wireless-icon-chevronDown');
		var body = item.querySelector('.wireless-ref-ssid-body');

		item.classList.remove('is-open');

		if (body)
			body.style.setProperty('display', 'none', 'important');

		if (toggle) {
			toggle.classList.remove('wireless-icon-chevronUp');
			toggle.classList.add('wireless-icon-chevronDown');
			toggle.title = _('Expand');
			toggle.setAttribute('aria-label', _('Expand'));
		}
	});

	if (card && open) {
		var body = card.querySelector('.wireless-ref-ssid-body');

		card.classList.add('is-open');

		if (body)
			body.style.setProperty('display', 'grid', 'important');

		if (button) {
			button.classList.remove('wireless-icon-chevronDown');
			button.classList.add('wireless-icon-chevronUp');
			button.title = _('Collapse');
			button.setAttribute('aria-label', _('Collapse'));
		}
	}
}

function makePayload(section, dryRun) {
	var radio = document.querySelector('[data-radio-config="%s"]'.format(section));
	var ssid = wirelessCardForSection(section);
	var payload = {
		section: section,
		dry_run: !!dryRun
	};
	var key;

	if (radio) {
		payload.type = 'wifi-device';
		payload.disabled = !radio.querySelector('[data-radio-field="enabled"]').checked;
		payload.channel = radio.querySelector('[data-radio-field="channel"]').value || 'auto';
		payload.htmode = radio.querySelector('[data-radio-field="htmode"]').value || '';
		payload.country = radio.querySelector('[data-radio-field="country"]').value || '';
	}

	if (ssid) {
		payload.type = 'wifi-iface';
		payload.mode = 'ap';
		payload.device = wirelessDeviceForSection(ssid, section) || undefined;
		payload.disabled = !fieldValue(ssid, 'enabled', true);
		payload.ssid = text(fieldValue(ssid, 'ssid', ''), '').trim();
		payload.network = fieldValue(ssid, 'network', 'lan');
		payload.encryption = fieldValue(ssid, 'security', 'none');
		payload.hidden = fieldValue(ssid, 'hidden', false);
		payload.isolate = fieldValue(ssid, 'isolate', false);
		payload.maxassoc = fieldValue(ssid, 'maxassoc', '');
		payload.band_steering = fieldValue(ssid, 'band_steering', false);
		payload.airtime_fairness = fieldValue(ssid, 'airtime_fairness', false);
		payload.download = fieldValue(ssid, 'download', '');
		payload.upload = fieldValue(ssid, 'upload', '');
		payload.air_vif_id = text(fieldValue(ssid, 'air_vif_id', ssid.getAttribute('data-wireless-vif')), '').trim();
		payload.air_link_id = wirelessValueForSection(ssid, section, 'data-wireless-link-ids');
		payload.air_mld_id = text(fieldValue(ssid, 'air_mld_id', ssid.getAttribute('data-wireless-mld')), '').trim();
		payload.mld_id = payload.air_mld_id;
		payload.security_ref = text(fieldValue(ssid, 'security_ref', ssid.getAttribute('data-wireless-security-ref')), '').trim();
		payload.network_ref = text(fieldValue(ssid, 'network_ref', ssid.getAttribute('data-wireless-network-ref')), '').trim();
		payload.qos_ref = text(fieldValue(ssid, 'qos_ref', ssid.getAttribute('data-wireless-qos-ref')), '').trim();
		payload.portal_ref = text(fieldValue(ssid, 'portal_ref', ssid.getAttribute('data-wireless-portal-ref')), '').trim();
		key = fieldValue(ssid, 'key', '');

		if (key)
			payload.key = key;
	}

	return payload;
}

function callSetPayload(payload) {
	return callWirelessSet(
		payload.section,
		payload.type,
		payload.device,
		payload.mode,
		payload.disabled,
		payload.ssid,
		payload.encryption,
		payload.key,
		payload.network,
		payload.channel,
		payload.htmode,
		payload.country,
		payload.hidden,
		payload.isolate,
		payload.maxassoc,
		payload.band_steering,
		payload.airtime_fairness,
		payload.download,
		payload.upload,
		payload.air_vif_id,
		payload.air_link_id,
		payload.air_mld_id,
		payload.mld_id,
		payload.security_ref,
		payload.network_ref,
		payload.qos_ref,
		payload.portal_ref,
		payload.dry_run
	);
}

function configuredSections() {
	var sections = [];
	var seen = {};
	var cards = document.querySelectorAll('[data-radio-config], [data-wireless-section], [data-wireless-sections]');

	for (var i = 0; i < cards.length; i++) {
		var raw = cards[i].getAttribute('data-radio-config') ||
			cards[i].getAttribute('data-wireless-sections') ||
			cards[i].getAttribute('data-wireless-section') || '';
		var items = raw.split(',');

		for (var j = 0; j < items.length; j++) {
			var section = items[j].trim();

			if (section && !seen[section]) {
				sections.push(section);
				seen[section] = true;
			}
		}
	}

	return sections;
}

function wirelessCardForSection(section) {
	var exact = document.querySelector('[data-wireless-section="%s"]'.format(section));
	var cards;

	if (exact)
		return exact;

	cards = document.querySelectorAll('[data-wireless-sections]');
	for (var i = 0; i < cards.length; i++) {
		var sections = (cards[i].getAttribute('data-wireless-sections') || '').split(',');

		for (var j = 0; j < sections.length; j++)
			if (sections[j].trim() == section)
				return cards[i];
	}

	return null;
}

function wirelessDeviceForSection(card, section) {
	var sections = (card && card.getAttribute('data-wireless-sections') || '').split(',');
	var devices = (card && card.getAttribute('data-wireless-devices') || '').split(',');

	for (var i = 0; i < sections.length; i++)
		if (sections[i].trim() == section && devices[i])
			return devices[i].trim();

	return card ? card.getAttribute('data-wireless-device') : null;
}

function wirelessValueForSection(card, section, attr) {
	var sections = (card && card.getAttribute('data-wireless-sections') || '').split(',');
	var values = (card && card.getAttribute(attr) || '').split(',');

	for (var i = 0; i < sections.length; i++)
		if (sections[i].trim() == section && values[i] !== undefined)
			return values[i].trim();

	return '';
}

function fieldValue(root, name, fallback) {
	var field = root ? root.querySelector('[data-field="%s"]'.format(name)) : null;

	if (!field)
		return fallback;

	if (field.type == 'checkbox')
		return !!field.checked;

	return field.value;
}

function showBackendError(env, fallback) {
	ui.addNotification(null, E('p', {}, backendError(env, fallback)), 'danger');
}

function confirmDeleteSsid(ssidName) {
	return new Promise(function(resolve) {
		var name = text(ssidName, _('this SSID'));

		ui.showModal(_('Delete SSID'), [
			E('div', { 'class': 'wireless-confirm-shell' }, [
				E('div', { 'class': 'wireless-confirm-modal' }, [
				E('div', { 'class': 'wireless-confirm-icon', 'aria-hidden': 'true' }, '!'),
				E('div', { 'class': 'wireless-confirm-copy' }, [
					E('h3', {}, _('Delete Wi-Fi network?')),
					E('p', {}, _('This action removes the SSID from the wireless configuration.')),
					E('div', { 'class': 'wireless-confirm-ssid' }, [
						E('span', {}, _('SSID')),
						E('strong', {}, name)
					])
				])
			]),
				E('div', { 'class': 'wireless-confirm-actions' }, [
				E('button', {
					'class': 'wireless-save',
					'type': 'button',
					'click': function() {
						ui.hideModal();
						resolve(false);
					}
				}, _('Cancel')),
				E('button', {
					'class': 'wireless-save is-danger',
					'type': 'button',
					'click': function() {
						ui.hideModal();
						resolve(true);
					}
				}, _('Delete SSID'))
			])
			])
		], 'cbi-modal');
	});
}

function refreshWireless() {
	return safeCall(callWirelessConfig).then(function(config) {
		if (!config || config.ok === false) {
			showBackendError(config, _('Wireless configuration was saved, but refresh failed.'));
			return;
		}

		lastConfig = config;
		window.setTimeout(function() { window.location.reload(); }, 500);
	});
}

function addWirelessSsid() {
	var ssidInput = E('input', {
		'class': 'wireless-config-input',
		'type': 'text',
		'maxlength': '32',
		'value': 'Guest WiFi'
	});
	var enabledInput = E('input', {
		'type': 'checkbox',
		'checked': 'checked'
	});
	var hiddenInput = E('input', { 'type': 'checkbox' });
	var isolateInput = E('input', { 'type': 'checkbox' });
	var bandSteeringInput = E('input', { 'type': 'checkbox' });
	var airtimeInput = E('input', { 'type': 'checkbox' });
	var deviceSelect = E('select', { 'class': 'wireless-config-select' }, [
		option('wifi1', _('2.4 GHz'), 'wifi1'),
		option('wifi0', _('5 GHz'), 'wifi1'),
		option('dual', _('2.4 GHz + 5 GHz'), 'wifi1')
	]);
	var networkSelect = E('select', { 'class': 'wireless-config-select' }, networkOptions('lan'));
	var securitySelect = E('select', { 'class': 'wireless-config-select' }, encryptionOptions('none'));
	var keyInput = E('input', {
		'class': 'wireless-config-input',
		'type': 'password',
		'maxlength': '63',
		'placeholder': _('8-63 characters')
	});
	var maxClientsInput = E('input', {
		'class': 'wireless-config-input',
		'type': 'number',
		'min': '1',
		'value': '64'
	});
	var downloadSelect = E('select', { 'class': 'wireless-config-select' }, limitOptions('50', '50'));
	var uploadSelect = E('select', { 'class': 'wireless-config-select' }, limitOptions('10', '10'));
	var summarySsid = E('strong', {}, 'Guest WiFi');
	var summaryBand = E('span', {}, _('2.4 GHz'));
	var summaryNetwork = E('span', {}, 'lan');
	var summarySecurity = E('span', {}, _('Open'));
	var summaryState = E('span', { 'class': 'wireless-status-pill is-on' }, _('Enabled'));

	function updateSummary() {
		summarySsid.textContent = ssidInput.value.trim() || _('Untitled SSID');
		summaryBand.textContent = deviceSelect.value == 'dual'
			? _('2.4 GHz + 5 GHz')
			: (deviceSelect.value == 'wifi1' ? _('2.4 GHz') : _('5 GHz'));
		summaryNetwork.textContent = networkSelect.options[networkSelect.selectedIndex].textContent;
		summarySecurity.textContent = encryptionLabel(securitySelect.value);
		summaryState.textContent = enabledInput.checked ? _('Enabled') : _('Disabled');
		summaryState.className = enabledInput.checked ? 'wireless-status-pill is-on' : 'wireless-status-pill';
	}

	deviceSelect.addEventListener('change', function() {
		updateSummary();
	});
	ssidInput.addEventListener('input', updateSummary);
	networkSelect.addEventListener('change', updateSummary);
	securitySelect.addEventListener('change', updateSummary);
	enabledInput.addEventListener('change', updateSummary);

	ui.showModal(_('Add SSID'), [
		E('div', { 'class': 'wireless-add-modal' }, [
			E('section', { 'class': 'wireless-add-editor' }, [
				E('div', { 'class': 'wireless-ref-section-title' }, _('Identity')),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Band')),
					deviceSelect
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('SSID name')),
					ssidInput
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Network')),
					networkSelect
				]),
				E('label', { 'class': 'wireless-check' }, [
					enabledInput,
					E('span', {}, _('Enable this SSID'))
				]),
				E('label', { 'class': 'wireless-check' }, [
					hiddenInput,
					E('span', {}, _('Hidden'))
				]),
				E('div', { 'class': 'wireless-ref-section-title' }, _('Security')),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Security mode')),
					securitySelect
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Passphrase')),
					keyInput
				]),
				E('div', { 'class': 'wireless-ref-section-title' }, _('Traffic controls')),
				E('label', { 'class': 'wireless-check wireless-span-2' }, [
					isolateInput,
					E('span', {}, _('Isolate clients from each other'))
				]),
				E('label', { 'class': 'wireless-toggle-card' }, [
					bandSteeringInput,
					E('span', {}, [
						E('strong', {}, _('Band steering')),
						E('small', {}, _('Guide capable clients toward the cleaner 5 GHz service.'))
					])
				]),
				E('label', { 'class': 'wireless-toggle-card' }, [
					airtimeInput,
					E('span', {}, [
						E('strong', {}, _('Airtime fairness')),
						E('small', {}, _('Balance wireless airtime across associated clients.'))
					])
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Maximum clients')),
					maxClientsInput
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Download limit (per client)')),
					downloadSelect
				]),
				E('label', { 'class': 'wireless-form-field' }, [
					E('span', {}, _('Upload limit (per client)')),
					uploadSelect
				])
			]),
			E('aside', { 'class': 'wireless-add-summary' }, [
				E('h3', {}, _('SSID Summary')),
				E('div', { 'class': 'wireless-add-summary-row' }, [
					E('span', {}, _('SSID name')),
					summarySsid
				]),
				E('div', { 'class': 'wireless-add-summary-row' }, [
					E('span', {}, _('Band')),
					summaryBand
				]),
				E('div', { 'class': 'wireless-add-summary-row' }, [
					E('span', {}, _('Network')),
					summaryNetwork
				]),
				E('div', { 'class': 'wireless-add-summary-row' }, [
					E('span', {}, _('Status')),
					summaryState
				]),
				E('div', { 'class': 'wireless-add-summary-row' }, [
					E('span', {}, _('Security mode')),
					summarySecurity
				]),
				E('p', { 'class': 'wireless-add-note' }, _('Add validates with airui.network wireless_add before writing. Advanced traffic controls are staged for the SSID editor after creation.'))
			])
		]),
		E('div', { 'class': 'wireless-add-actions' }, [
			E('button', { 'class': 'wireless-save', 'type': 'button', 'click': ui.hideModal }, _('Cancel')),
			E('button', {
				'class': 'wireless-save is-primary',
				'type': 'button',
				'click': function() {
					var ssidName = ssidInput.value.trim();
					var devices = deviceSelect.value == 'dual' ? [ 'wifi1', 'wifi0' ] : [ deviceSelect.value ];
					var logicalVifId = generatedVifId();

					if (!ssidName) {
						ui.addNotification(null, E('p', {}, _('SSID name is required.')), 'danger');
						return;
					}

					var payloads = devices.map(function(device, index) {
						return {
							section: '',
							type: 'wifi-iface',
							device: device,
							mode: 'ap',
							network: networkSelect.value,
							ssid: ssidName,
							encryption: securitySelect.value,
							key: keyInput.value,
							disabled: !enabledInput.checked,
							hidden: hiddenInput.checked,
							isolate: isolateInput.checked,
							maxassoc: maxClientsInput.value,
							band_steering: bandSteeringInput.checked,
							airtime_fairness: airtimeInput.checked,
							download: downloadSelect.value,
							upload: uploadSelect.value,
							air_vif_id: logicalVifId
						};
					});

					return Promise.all(payloads.map(function(payload) {
						return callWirelessAdd(
							'',
							payload.type,
							payload.device,
							payload.mode,
							payload.network,
							payload.ssid,
							payload.encryption,
							payload.key || '',
							payload.disabled,
							true
						);
					})).then(function(dryRuns) {
						for (var i = 0; i < dryRuns.length; i++) {
							if (!dryRuns[i] || dryRuns[i].ok === false) {
								showBackendError(dryRuns[i], _('SSID validation failed.'));
								return null;
							}
						}

						return Promise.all(payloads.map(function(payload) {
							return callWirelessAdd(
								'',
								payload.type,
								payload.device,
								payload.mode,
								payload.network,
								payload.ssid,
								payload.encryption,
								payload.key || '',
								payload.disabled,
								false
							);
						}));
					}).then(function(result) {
						if (!result)
							return;

						for (var i = 0; i < result.length; i++) {
							if (!result[i] || result[i].ok === false) {
								showBackendError(result[i], _('SSID creation failed.'));
								return;
							}

							if (result[i].data && result[i].data.section)
								payloads[i].section = result[i].data.section;
						}

						return Promise.all(payloads.map(function(payload) {
							if (!payload.section)
								return Promise.resolve({ ok: true });

							payload.dry_run = false;
							return callSetPayload(payload).catch(featureNotReady);
						}));
					}).then(function(result) {
						if (!result)
							return;

						for (var i = 0; i < result.length; i++) {
							if (!result[i] || result[i].ok === false) {
								showBackendError(result[i], _('SSID created, but advanced options could not be saved.'));
								return;
							}
						}

						ui.hideModal();
						ui.addNotification(null, E('p', {}, _('SSID added.')), 'info');
						return refreshWireless();
					}).catch(function(err) {
						showBackendError(featureNotReady(err), _('SSID creation failed.'));
					});
				}
			}, _('Add SSID'))
		])
	], 'cbi-modal');
}

function deleteWirelessSsid(section, ssidName) {
	return confirmDeleteSsid(ssidName || section).then(function(confirmed) {
		if (!confirmed)
			return null;

		return callWirelessDelete(section, true);
	}).then(function(dryRun) {
		if (!dryRun)
			return;

		if (!dryRun || dryRun.ok === false) {
			showBackendError(dryRun, _('SSID delete validation failed.'));
			return;
		}

		return callWirelessDelete(section, false);
	}).then(function(result) {
		if (!result)
			return;

		if (result.ok === false) {
			showBackendError(result, _('SSID delete failed.'));
			return;
		}

		ui.addNotification(null, E('p', {}, _('SSID deleted.')), 'info');
		return refreshWireless();
	}).catch(function(err) {
		showBackendError(featureNotReady(err), _('SSID delete failed.'));
	});
}

function saveWireless(apply) {
	var sections = configuredSections();
	var dryRuns = sections.map(function(section) {
		return callSetPayload(makePayload(section, true)).catch(featureNotReady);
	});

	var save = Promise.all(dryRuns).then(function(results) {
		for (var i = 0; i < results.length; i++) {
			if (results[i].feature_not_ready) {
				ui.addNotification(null, E('p', {}, _('Wireless backend is not ready for saving on this firmware.')), 'info');
				return;
			}

			if (!results[i] || results[i].ok === false) {
				showBackendError(results[i], _('Wireless validation failed.'));
				return;
			}
		}

		return Promise.all(sections.map(function(section) {
			return callSetPayload(makePayload(section, false)).catch(featureNotReady);
		})).then(function(applied) {
			for (var j = 0; j < applied.length; j++) {
				if (applied[j].feature_not_ready) {
					ui.addNotification(null, E('p', {}, _('Wireless backend is not ready for saving on this firmware.')), 'info');
					return;
				}

				if (!applied[j] || applied[j].ok === false) {
					showBackendError(applied[j], _('Wireless save failed.'));
					return;
				}
			}

			ui.addNotification(null, E('p', {}, apply
				? _('Wireless configuration saved and applied.')
				: _('Wireless configuration saved.')), 'info');

			return refreshWireless();
		});
	});

	return applyStatus.track(save, _('Wireless configuration'));
}

function backendUnavailable(env) {
	return E('div', { 'class': 'airdash wireless-page wireless-ref-console' }, [
		E('section', { 'class': 'wireless-ref-head' }, [
			E('div', { 'class': 'wireless-ref-title-block' }, [
				E('h1', {}, _('Wireless Settings')),
				E('p', {}, _('Configure radios, SSIDs, security and per-client wireless traffic controls.'))
			])
		]),
		E('section', { 'class': 'wireless-ref-panel' }, [
			E('div', { 'class': 'wireless-panel-head' }, [
				E('div', {}, [
					E('h2', {}, env && env.feature_not_ready ? _('Feature not ready') : _('Backend unavailable')),
					E('p', {}, backendError(env, _('The AirUI local backend did not return a healthy response.')))
				])
			]),
			E('div', { 'class': 'client-empty' }, _('Wireless settings will appear here when the airui backend is available.'))
		])
	]);
}

function radioCard(info, cfg, runtime) {
	var disabled = isDisabled(cfg, runtime);
	var clients = clientCount(runtime);
	var runtimeCfg = runtime.config || runtime;
	var channel = text(cfg.channel || runtimeCfg.channel, 'auto');
	var htmode = text(cfg.htmode || runtimeCfg.htmode, isBand24(info.bandLabel) ? 'HE40' : 'HE80');
	var txpower = text(cfg.txpower || runtimeCfg.txpower, '');
	var country = text(cfg.country || runtimeCfg.country, 'IN');

	return E('article', {
		'class': 'wireless-advanced-radio',
		'data-radio-config': info.device
	}, [
		E('div', { 'class': 'wireless-advanced-radio-head' }, [
			E('div', { 'class': 'wireless-ref-title' }, [
				miniIcon('radio'),
				E('div', {}, [
					E('h3', {}, info.bandLabel),
					E('p', {}, [
						E('span', {}, _('Device: %s').format(info.device)),
						E('b', {}, '·'),
						E('span', {}, _('%d clients').format(clients))
					])
				])
			]),
			pill(!disabled)
		]),
		E('div', { 'class': 'wireless-advanced-radio-form' }, [
			E('label', { 'class': 'wireless-toggle-card wireless-radio-toggle' }, [
				E('input', { 'type': 'checkbox', 'data-radio-field': 'enabled', 'checked': disabled ? null : 'checked' }),
				E('span', {}, [
					E('strong', {}, _('Radio enabled')),
					E('small', {}, _('Allow this radio to advertise configured SSIDs.'))
				])
			]),
			E('label', { 'class': 'wireless-form-field' }, [
				E('span', {}, _('Channel')),
				E('select', { 'class': 'wireless-config-select', 'data-radio-field': 'channel' }, channelOptions(channel, info.bandLabel))
			]),
			E('label', { 'class': 'wireless-form-field' }, [
				E('span', {}, _('Channel width')),
				E('select', { 'class': 'wireless-config-select', 'data-radio-field': 'htmode' }, widthOptions(htmode, info.bandLabel))
			]),
			E('label', { 'class': 'wireless-form-field' }, [
				E('span', {}, _('TX power')),
				E('select', { 'class': 'wireless-config-select', 'data-radio-field': 'txpower' }, txPowerOptions(txpower, info.bandLabel))
			]),
			E('label', { 'class': 'wireless-form-field' }, [
				E('span', {}, _('Country / region')),
				E('select', { 'class': 'wireless-config-select', 'data-radio-field': 'country' }, [
					option('IN', _('India'), country),
					option('US', _('United States'), country),
					option('EU', _('Europe'), country),
					option('00', _('World'), country)
				])
			])
		]),
		E('div', { 'class': 'wireless-ref-note' }, [
			E('span', {}, 'i'),
			E('strong', {}, _('Auto-channel available')),
			E('b', {}, _('Apply Changes validates with the AirUI backend before writing.'))
		])
	]);
}

function sectionsForVif(vif) {
	var links = Array.isArray(vif && vif.links) ? vif.links : [];
	var sections = [];

	for (var i = 0; i < links.length; i++)
		if (links[i] && links[i].uci_section)
			sections.push(links[i].uci_section);

	return sections;
}

function devicesForVif(vif) {
	var links = Array.isArray(vif && vif.links) ? vif.links : [];
	var devices = [];

	for (var i = 0; i < links.length; i++) {
		var radioId = links[i] && links[i].radio_id;

		if (radioId == 'radio_0')
			devices.push('wifi1');
		else if (radioId == 'radio_1')
			devices.push('wifi0');
		else if (radioId == 'radio_2')
			devices.push('wifi2');
		else
			devices.push(links[i] && links[i].device || '');
	}

	return devices;
}

function enterpriseVifs(configEnv) {
	var enterprise = enterpriseFromEnvelope(configEnv);

	return Array.isArray(enterprise.vifs) ? enterprise.vifs : [];
}

function deleteWirelessVif(vif, ssidName) {
	var sections = sectionsForVif(vif);

	if (!sections.length)
		return;

	return confirmDeleteSsid(ssidName || vif.vif_id || sections[0]).then(function(confirmed) {
		if (!confirmed)
			return null;

		return Promise.all(sections.map(function(section) {
		return callWirelessDelete(section, true).catch(featureNotReady);
		}));
	}).then(function(dryRuns) {
		if (!dryRuns)
			return null;

		for (var i = 0; i < dryRuns.length; i++) {
			if (!dryRuns[i] || dryRuns[i].ok === false) {
				showBackendError(dryRuns[i], _('SSID delete validation failed.'));
				return null;
			}
		}

		return Promise.all(sections.map(function(section) {
			return callWirelessDelete(section, false).catch(featureNotReady);
		}));
	}).then(function(result) {
		if (!result)
			return;

		for (var i = 0; i < result.length; i++) {
			if (!result[i] || result[i].ok === false) {
				showBackendError(result[i], _('SSID delete failed.'));
				return;
			}
		}

		ui.addNotification(null, E('p', {}, _('Wi-Fi network deleted.')), 'info');
		return refreshWireless();
	});
}

function vifRuntimeRows(vif) {
	var links = Array.isArray(vif && vif.links) ? vif.links : [];

	if (!links.length)
		return E('div', { 'class': 'wireless-link-empty' }, _('No runtime links reported.'));

	return E('div', { 'class': 'wireless-link-grid' }, links.map(function(link) {
		return E('div', { 'class': 'wireless-link-row' }, [
			E('strong', {}, _('Link %s').format(text(link.link_id, '0'))),
			E('span', {}, _('Band: %s').format(bandLabelFromKey(link.band))),
			E('span', {}, _('Radio: %s').format(text(link.radio_id))),
			E('span', {}, _('PHY: %s').format(text(link.phy))),
			E('span', {}, _('Interface: %s').format(text(link.ifname))),
			E('span', {}, _('State: %s').format(text(link.state, 'unknown').toUpperCase()))
		]);
	}));
}

function vifCard(vif, values, runtime, index) {
	var identity = vif.identity || {};
	var configuration = vif.configuration || {};
	var deployment = vif.deployment || {};
	var mlo = deployment.mlo || {};
	var sections = sectionsForVif(vif);
	var devices = devicesForVif(vif);
	var primarySection = sections[0] || vif.vif_id || '';
	var cfg = sectionConfig(values, primarySection);
	var firstLink = Array.isArray(vif.links) && vif.links[0] ? vif.links[0] : {};
	var info = {
		section: primarySection,
		device: devices[0] || cfg.device || '',
		bandKey: firstLink.band || (deployment.bands && deployment.bands[0]) || '',
		bandLabel: bandLabelFromKey(firstLink.band || (deployment.bands && deployment.bands[0]))
	};
	var runtimeCfg = interfaceRuntime(runtime, info);
	var enabled = configuration.enabled !== false && !isDisabled(cfg, runtimeCfg);
	var ssid = text(identity.ssid || cfg.ssid, _('Untitled SSID'));
	var hidden = String(cfg.hidden || runtimeCfg.hidden || '0') == '1' || cfg.hidden === true || runtimeCfg.hidden === true;
	var isolate = String(cfg.isolate || runtimeCfg.isolate || '0') == '1' || cfg.isolate === true || runtimeCfg.isolate === true;
	var bandSteering = String(cfg.band_steering || runtimeCfg.band_steering || '0') == '1' || cfg.band_steering === true || runtimeCfg.band_steering === true;
	var airtimeFairness = String(cfg.airtime_fairness || runtimeCfg.airtime_fairness || '0') == '1' || cfg.airtime_fairness === true || runtimeCfg.airtime_fairness === true;
	var maxassoc = text(cfg.maxassoc, '64');
	var download = text(cfg.downrate || cfg.download || runtimeCfg.downrate || runtimeCfg.download, '');
	var upload = text(cfg.uprate || cfg.upload || runtimeCfg.uprate || runtimeCfg.upload, '');
	var networkName = text((configuration.network_ref || '').replace(/^net_/, '') || cfg.network, 'lan');
	var encryption = text((configuration.security_ref || '').replace(/^sec_/, '') || cfg.encryption, 'none');
	var bands = Array.isArray(deployment.bands) ? deployment.bands : [];
	var linkIds = Array.isArray(vif.links) ? vif.links.map(function(link) { return text(link.link_id, '0'); }) : [];
	var bandText = bands.length ? bands.map(bandLabelFromKey).join(' + ') : info.bandLabel;
	var clients = Array.isArray(vif.links)
		? vif.links.reduce(function(total, link) {
			return total + clientCount(runtime[link.uci_section] || {});
		}, 0)
		: clientCount(runtimeCfg);
	var head = E('div', { 'class': 'wireless-ref-ssid-head' }, [
		E('div', { 'class': 'wireless-ssid-name-cell wireless-ref-ssid-toggle-label' }, [
			miniIcon('wifi'),
			ssidSignal(enabled),
			E('strong', {}, ssid)
		]),
		E('div', { 'class': 'wireless-table-cell' }, [
			bandChips(bands, info.bandKey)
		]),
		E('div', { 'class': 'wireless-table-cell' }, encryptionLabel(cfg.encryption || encryption)),
		E('div', { 'class': 'wireless-table-cell is-linklike' }, networkName),
		E('div', { 'class': 'wireless-table-cell' }, [
			pill(enabled)
		]),
		E('div', { 'class': 'wireless-ref-actions' }, [
			iconButton('trash', 'wireless-ref-icon-button is-danger', _('Delete'), function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				deleteWirelessVif(vif, ssid);
			}),
			E('button', {
				'class': 'wireless-ref-icon-button wireless-ref-ssid-toggle wireless-icon-chevronDown',
				'type': 'button',
				'title': _('Expand'),
				'aria-label': _('Expand')
			})
		])
	]);
	var body = E('div', { 'class': 'wireless-ref-ssid-body' }, [
		E('div', { 'class': 'wireless-ref-form' }, [
			E('div', { 'class': 'wireless-ref-section-title' }, _('Identity')),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('SSID name')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'text',
					'maxlength': '32',
					'data-field': 'ssid',
					'value': ssid
				})
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Network')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'network' }, networkOptions(cfg.network || networkName))
			]),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'enabled', 'checked': enabled ? 'checked' : null }),
				E('span', {}, _('Enable this Wi-Fi network'))
			]),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'hidden', 'checked': hidden ? 'checked' : null }),
				E('span', {}, _('Hidden SSID'))
			]),
			E('div', { 'class': 'wireless-ref-section-title' }, _('Security')),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Security mode')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'security' }, encryptionOptions(cfg.encryption || encryption))
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Passphrase')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'password',
					'maxlength': '63',
					'data-field': 'key',
					'placeholder': _('Unchanged')
				})
			]),
			E('div', { 'class': 'wireless-ref-section-title' }, _('Advanced')),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'isolate', 'checked': isolate ? 'checked' : null }),
				E('span', {}, _('Isolate clients from each other'))
			]),
			E('label', { 'class': 'wireless-toggle-card wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'band_steering', 'checked': bandSteering ? 'checked' : null }),
				E('span', {}, [
					E('strong', {}, _('Band steering')),
					E('small', {}, _('Guide capable clients toward the cleaner band.'))
				])
			]),
			E('label', { 'class': 'wireless-toggle-card wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'airtime_fairness', 'checked': airtimeFairness ? 'checked' : null }),
				E('span', {}, [
					E('strong', {}, _('Airtime fairness')),
					E('small', {}, _('Balance wireless airtime across associated clients.'))
				])
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Maximum clients')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'number',
					'min': '1',
					'data-field': 'maxassoc',
					'value': maxassoc
				})
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Download limit (per client)')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'download' }, limitOptions(download, '50'))
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Upload limit (per client)')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'upload' }, limitOptions(upload, '10'))
			])
		])
	]);

	return E('div', { 'class': 'wireless-ref-ssid-shell' }, [
		E('div', {
			'class': enabled ? 'wireless-ref-ssid is-enabled' : 'wireless-ref-ssid',
			'data-wireless-section': primarySection,
			'data-wireless-sections': sections.join(','),
			'data-wireless-devices': devices.join(','),
			'data-wireless-link-ids': linkIds.join(','),
			'data-wireless-device': devices[0] || '',
			'data-wireless-vif': vif.vif_id || '',
			'data-wireless-mld': mlo.mld_id || cfg.air_mld_id || cfg.mld_id || '',
			'data-wireless-security-ref': configuration.security_ref || cfg.security_ref || '',
			'data-wireless-network-ref': configuration.network_ref || cfg.network_ref || '',
			'data-wireless-qos-ref': configuration.qos_ref || cfg.qos_ref || '',
			'data-wireless-portal-ref': configuration.portal_ref || cfg.portal_ref || ''
		}, [ head, body ])
	]);
}

function ssidCard(info, cfg, runtime, index) {
	var disabled = isDisabled(cfg, runtime);
	var enabled = !disabled;
	var runtimeCfg = runtime.config || runtime;
	var ssid = text(cfg.ssid || runtimeCfg.ssid, info.bandLabel == '2.4 GHz' ? 'AIR-2G-8BEA' : 'AIR-5G-8BEB');
	var networkName = text(cfg.network || (Array.isArray(runtimeCfg.network) ? runtimeCfg.network[0] : runtimeCfg.network), 'lan');
	var encryption = text(cfg.encryption || runtimeCfg.encryption, 'none');
	var hidden = String(cfg.hidden || runtimeCfg.hidden || '0') == '1' || cfg.hidden === true || runtimeCfg.hidden === true;
	var isolate = String(cfg.isolate || runtimeCfg.isolate || '0') == '1' || cfg.isolate === true || runtimeCfg.isolate === true;
	var bandSteering = String(cfg.band_steering || runtimeCfg.band_steering || '0') == '1' || cfg.band_steering === true || runtimeCfg.band_steering === true;
	var airtimeFairness = String(cfg.airtime_fairness || runtimeCfg.airtime_fairness || '0') == '1' || cfg.airtime_fairness === true || runtimeCfg.airtime_fairness === true;
	var maxassoc = text(cfg.maxassoc, '64');
	var download = text(cfg.downrate || cfg.download || runtimeCfg.downrate || runtimeCfg.download, '');
	var upload = text(cfg.uprate || cfg.upload || runtimeCfg.uprate || runtimeCfg.upload, '');
	var clients = clientCount(runtime);
	var head = E('div', { 'class': 'wireless-ref-ssid-head' }, [
		E('div', { 'class': 'wireless-ssid-name-cell wireless-ref-ssid-toggle-label' }, [
			miniIcon('wifi'),
			ssidSignal(enabled),
			E('strong', {}, ssid)
		]),
		E('div', { 'class': 'wireless-table-cell' }, [
			bandChips([ info.bandKey ], info.bandKey)
		]),
		E('div', { 'class': 'wireless-table-cell' }, encryptionLabel(encryption)),
		E('div', { 'class': 'wireless-table-cell is-linklike' }, networkName),
		E('div', { 'class': 'wireless-table-cell' }, [
			pill(enabled)
		]),
		E('div', { 'class': 'wireless-ref-actions' }, [
			iconButton('trash', 'wireless-ref-icon-button is-danger', _('Delete'), function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				deleteWirelessSsid(info.section, ssid);
			}),
			E('button', {
				'class': 'wireless-ref-icon-button wireless-ref-ssid-toggle wireless-icon-chevronDown',
				'type': 'button',
				'title': _('Expand'),
				'aria-label': _('Expand')
			})
		])
	]);
	var body = E('div', { 'class': 'wireless-ref-ssid-body' }, [
		E('div', { 'class': 'wireless-ref-form' }, [
			E('div', { 'class': 'wireless-ref-section-title' }, _('Identity')),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('SSID name')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'text',
					'maxlength': '32',
					'data-field': 'ssid',
					'value': ssid
				})
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Network')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'network' }, networkOptions(networkName))
			]),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'enabled', 'checked': enabled ? 'checked' : null }),
				E('span', {}, _('Enable this SSID'))
			]),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'hidden', 'checked': hidden ? 'checked' : null }),
				E('span', {}, _('Hidden'))
			]),
			E('div', { 'class': 'wireless-ref-section-title' }, _('Security')),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Security mode')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'security' }, encryptionOptions(encryption))
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Passphrase')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'password',
					'maxlength': '63',
					'data-field': 'key',
					'placeholder': _('Unchanged')
				})
			]),
			E('div', { 'class': 'wireless-ref-section-title' }, _('Traffic controls')),
			E('label', { 'class': 'wireless-check wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'isolate', 'checked': isolate ? 'checked' : null }),
				E('span', {}, _('Isolate clients from each other'))
			]),
			E('label', { 'class': 'wireless-toggle-card wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'band_steering', 'checked': bandSteering ? 'checked' : null }),
				E('span', {}, [
					E('strong', {}, _('Band steering')),
					E('small', {}, _('Guide capable clients toward the cleaner 5 GHz service.'))
				])
			]),
			E('label', { 'class': 'wireless-toggle-card wireless-span-2' }, [
				E('input', { 'type': 'checkbox', 'data-field': 'airtime_fairness', 'checked': airtimeFairness ? 'checked' : null }),
				E('span', {}, [
					E('strong', {}, _('Airtime fairness')),
					E('small', {}, _('Balance wireless airtime across associated clients.'))
				])
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Maximum clients')),
				E('input', {
					'class': 'wireless-config-input',
					'type': 'number',
					'min': '1',
					'data-field': 'maxassoc',
					'value': maxassoc
				})
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Download limit (per client)')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'download' }, limitOptions(download, '50'))
			]),
			E('label', { 'class': 'wireless-form-field wireless-span-2' }, [
				E('span', {}, _('Upload limit (per client)')),
				E('select', { 'class': 'wireless-config-select', 'data-field': 'upload' }, limitOptions(upload, '10'))
			])
		])
	]);

	return E('div', { 'class': 'wireless-ref-ssid-shell' }, [
		E('div', {
			'class': enabled ? 'wireless-ref-ssid is-enabled' : 'wireless-ref-ssid',
			'data-wireless-section': info.section,
			'data-wireless-device': info.device
		}, [ head, body ])
	]);
}

function radioSettings(configEnv) {
	var values = valuesFromEnvelope(configEnv);
	var runtime = runtimeFromEnvelope(configEnv);

	return E('section', { 'class': 'wireless-ref-panel wireless-advanced-panel', 'id': 'radio-configuration' }, [
		E('div', { 'class': 'wireless-panel-head' }, [
			E('div', {}, [
				E('h2', {}, _('Radio Configuration')),
				E('p', {}, _('Configure radio settings for all bands.'))
			]),
			E('span', { 'class': 'wireless-optimize-link' }, _('%d radios').format(RADIO_SECTIONS.length))
		]),
		E('div', { 'class': 'wireless-advanced-grid' }, RADIO_SECTIONS.map(function(info) {
			return radioCard(info, radioConfig(values, info), radioRuntime(runtime, info));
		}))
	]);
}

function serviceTable(configEnv) {
	var values = valuesFromEnvelope(configEnv);
	var runtime = runtimeFromEnvelope(configEnv);
	var vifs = enterpriseVifs(configEnv);
	var sections = ifaceSections(values);
	var count = vifs.length || sections.length;

	return E('section', { 'class': 'wireless-ref-panel wireless-ref-ssid-management', 'id': 'ssid-list' }, [
		E('div', { 'class': 'wireless-panel-head' }, [
			E('div', {}, [
				E('h2', {}, _('SSID List')),
				E('p', {}, _('Create and manage your Wi-Fi networks.'))
			]),
			E('div', { 'class': 'wireless-ref-panel-actions' }, [
				E('label', { 'class': 'wireless-ref-search wireless-ref-search-inline' }, [
					E('span', {}, '⌕'),
					E('input', {
						'type': 'search',
						'placeholder': _('Search SSID...'),
						'data-wireless-search': '1',
						'aria-label': _('Search SSID')
					})
				]),
				E('button', {
					'class': 'wireless-save is-primary',
					'type': 'button',
					'click': addWirelessSsid
				}, _('+ Add SSID'))
			])
		]),
		E('div', { 'class': 'wireless-ref-ssid-table' }, [
			E('div', { 'class': 'wireless-ref-ssid-table-head' }, [
				E('span', {}, _('SSID Name')),
				E('span', {}, _('Bands')),
				E('span', {}, _('Security')),
				E('span', {}, _('Network')),
				E('span', {}, _('Status')),
				E('span', {}, _('Actions'))
			]),
			E('div', { 'class': 'wireless-ref-ssid-list' }, vifs.length
				? vifs.map(function(vif, index) {
				return vifCard(vif, values, runtime, index);
				})
				: sections.map(function(section, index) {
				var cfg = sectionConfig(values, section);
				var info = infoForIface(section, cfg);
				return ssidCard(info, cfg, interfaceRuntime(runtime, info), index);
				}))
		]),
		E('div', { 'class': 'wireless-table-footer' }, _('Showing 1 to %d of %d SSIDs').format(count, count))
	]);
}

function toolbarActions(caps) {
	var children = [];

	if (caps && caps.feature_not_ready)
		children.push(E('span', { 'class': 'wireless-status-pill' }, _('Capabilities pending')));

	return E('div', { 'class': 'wireless-ref-actions-main' }, children);
}

function bindSsidAccordion(root) {
	root.querySelectorAll('.wireless-ref-ssid').forEach(function(card) {
		var head = card.querySelector('.wireless-ref-ssid-head');
		var body = card.querySelector('.wireless-ref-ssid-body');
		var toggle = card.querySelector('.wireless-ref-ssid-toggle');
		var danger = card.querySelector('.wireless-ref-icon-button.is-danger');

		function sync() {
			var open = card.classList.contains('is-open');

			if (body)
				body.style.setProperty('display', open ? 'grid' : 'none', 'important');

			if (toggle) {
				toggle.title = open ? _('Collapse') : _('Expand');
				toggle.setAttribute('aria-label', open ? _('Collapse') : _('Expand'));
			}
		}

		if (head)
			head.addEventListener('click', function(ev) {
				if (ev.target && ev.target.closest && ev.target.closest('.wireless-ref-icon-button.is-danger'))
					return;

				ev.preventDefault();
				toggleSsidCard(card);
			});

		if (toggle)
			toggle.addEventListener('click', function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				toggleSsidCard(card);
			});

		if (danger)
			danger.addEventListener('click', function(ev) {
				ev.stopPropagation();
			});

		sync();
	});
}

function bindWirelessSearch(root) {
	var inputs = root.querySelectorAll('[data-wireless-search]');
	var rows = root.querySelectorAll('.wireless-ref-ssid-shell');

	if (!inputs.length)
		return;

	inputs.forEach(function(input) {
		input.addEventListener('input', function() {
			var query = input.value.trim().toLowerCase();

			inputs.forEach(function(peer) {
				if (peer !== input)
					peer.value = input.value;
			});

			rows.forEach(function(row) {
				var haystack = (row.textContent || '').toLowerCase();
				var match = !query || haystack.indexOf(query) >= 0;

				row.style.display = match ? '' : 'none';
			});
		});
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			safeCall(callHealth),
			safeCall(callCapabilities),
			safeCall(callWirelessConfig),
			safeCall(callInterfaceConfig)
		]);
	},

	render: function(data) {
		var health = data[0];
		var caps = data[1];
		var config = data[2];
		var interfaces = data[3];

		if (config && config.feature_not_ready)
			return backendUnavailable(config);

		if (!config || config.ok === false)
			return backendUnavailable(config || health);

		lastConfig = config;
		lastInterfaceConfig = interfaces && interfaces.ok !== false ? interfaces : null;

		var root = E('div', { 'class': 'airdash wireless-page wireless-ref-console' }, [
			E('section', { 'class': 'wireless-ref-head' }, [
				E('div', { 'class': 'wireless-ref-title-block' }, [
					E('span', { 'class': 'air-page-eyebrow' }, _('Network')),
					E('h1', {}, _('Wireless (SSID)')),
					E('p', {}, _('Create and manage Wi-Fi SSIDs and configure radio settings.'))
				]),
				E('div', { 'class': 'wireless-ref-toolbar' }, [
					E('button', { 'class': 'wireless-save is-primary', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Refresh')),
					E('small', { 'class': 'air-page-updated' }, _('Updated just now'))
				])
			]),
			E('nav', { 'class': 'wireless-tabs', 'aria-label': _('Wireless sections') }, [
				E('a', { 'class': 'is-active', 'href': '#ssid-list' }, _('SSIDs')),
				E('a', { 'href': '#radio-configuration' }, _('Radio Configuration'))
			]),
			serviceTable(config),
			radioSettings(config),
			E('section', { 'class': 'wireless-ref-applybar' }, [
				E('div', {}, [
					E('span', {}, 'i'),
					E('strong', {}, _('Changes made on this page will be applied to the device after you click Apply Changes.'))
				]),
				E('div', {}, [
					E('button', { 'class': 'wireless-save', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Discard Changes')),
					E('button', { 'class': 'wireless-save is-primary', 'type': 'button', 'click': function() { saveWireless(true); } }, _('Apply Changes'))
				])
			])
			]);

		bindSsidAccordion(root);
		bindWirelessSearch(root);

		return root;
	}
});
