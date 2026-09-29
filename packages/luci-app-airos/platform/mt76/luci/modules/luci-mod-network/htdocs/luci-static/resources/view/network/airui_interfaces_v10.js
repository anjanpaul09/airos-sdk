'use strict';
'require view';
'require rpc';
'require ui';
'require airui.apply_status_v2 as applyStatus';
'require airui.action_dialog as actionDialog';

var callHealth = rpc.declare({
	object: 'airui.system',
	method: 'health',
	expect: { '': {} }
});

var callControllerStatus = rpc.declare({
	object: 'airui.mode',
	method: 'controller_status',
	expect: { '': {} }
});

var callInterfaceConfig = rpc.declare({
	object: 'airui.network',
	method: 'interface_config',
	expect: { '': {} }
});

var callInterfaceValidate = rpc.declare({
	object: 'airui.network',
	method: 'interface_validate',
	params: [
		'type',
		'name',
		'vlan_id',
		'parent_device',
		'bridge_name',
		'proto',
		'ipaddr',
		'netmask',
		'dhcp',
		'firewall',
		'dry_run'
	],
	expect: { '': {} }
});

var callInterfaceAdd = rpc.declare({
	object: 'airui.network',
	method: 'interface_add',
	params: [
		'type',
		'name',
		'vlan_id',
		'parent_device',
		'bridge_name',
		'proto',
		'ipaddr',
		'netmask',
		'dhcp',
		'firewall',
		'dry_run'
	],
	expect: { '': {} }
});

var callInterfaceSet = rpc.declare({
	object: 'airui.network',
	method: 'interface_set',
	params: [
		'type',
		'name',
		'vlan_id',
		'parent_device',
		'bridge_name',
		'proto',
		'ipaddr',
		'netmask',
		'dhcp',
		'firewall',
		'dry_run'
	],
	expect: { '': {} }
});

var callInterfaceDelete = rpc.declare({
	object: 'airui.network',
	method: 'interface_delete',
	params: [ 'name', 'delete_ssid_mappings', 'dry_run' ],
	expect: { '': {} }
});

var callInterfaceApply = rpc.declare({
	object: 'airui.network',
	method: 'interface_apply',
	params: [ 'commit', 'restart', 'services', 'rollback_timeout' ],
	expect: { '': {} }
});

var lastConfig = null;
var pageRefs = {};
var cloudManaged = false;

function cloudManagedNotice() {
	return E('section', { 'class': 'wireless-ref-panel wireless-read-only-notice' }, [
		E('strong', {}, _('Cloud-managed configuration')),
		E('span', {}, _('Network interfaces are controlled by AirPro Cloud and are available here as read-only.'))
	]);
}

function cloudManagedError() {
	ui.addNotification(null, E('p', {}, _('Network interface configuration is managed by AirPro Cloud.')), 'info');
	return Promise.reject(new Error(_('Network interface configuration is managed by AirPro Cloud.')));
}

function t(value, fallback) {
	if (value === null || value === undefined || value === '')
		return fallback || '-';

	return String(value);
}

function backendError(env, fallback) {
	if (env && Array.isArray(env.errors) && env.errors[0])
		return env.errors[0].message || env.errors[0].code || fallback;

	return fallback || _('Backend request failed.');
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

function isTimeoutError(err) {
	var msg = err && (err.message || err.toString && err.toString()) || '';

	return /timed out|timeout|XHR/i.test(msg);
}

function dataOf(env) {
	return env && env.ok !== false && env.data ? env.data : {};
}

function uciOf(env) {
	return dataOf(env).uci || {};
}

function uciValues(section) {
	if (!section)
		return {};

	return section.values || section;
}

function runtimeOf(env) {
	return dataOf(env).runtime || {};
}

function networkSections(env) {
	var uci = uciOf(env);
	var network = uciValues(uci.network || uci.values || {});
	var result = [];

	Object.keys(network || {}).sort().forEach(function(name) {
		var cfg = network[name] || {};
		var type = cfg['.type'] || cfg.type;

		if (type == 'interface' || cfg.proto)
			result.push({ name: name, cfg: cfg });
	});

	return result;
}

function networkConfigSection(env, name) {
	var uci = uciOf(env);
	var network = uciValues(uci.network || uci.values || {});

	return network[name] || {};
}

function wirelessSections(env) {
	var uci = uciOf(env);
	var wireless = uciValues(uci.wireless || uci.values || {});
	var result = [];

	Object.keys(wireless || {}).sort().forEach(function(name) {
		var cfg = wireless[name] || {};

		if ((cfg['.type'] || cfg.type) == 'wifi-iface')
			result.push({
				section: name,
				ssid: t(cfg.ssid, name),
				network: t(cfg.network, '-')
			});
	});

	return result;
}

function dhcpSection(env, name) {
	var dhcp = uciValues(uciOf(env).dhcp || {});
	var exact = dhcp[name];
	var match = null;

	if (exact && (exact['.type'] || exact.type) == 'dhcp')
		return exact;

	Object.keys(dhcp).some(function(sectionName) {
		var section = dhcp[sectionName] || {};

		if ((section['.type'] || section.type) == 'dhcp' && section.interface == name) {
			match = section;
			return true;
		}

		return false;
	});

	return match || {};
}

function dhcpEnabled(section) {
	return !!(section && section.interface && String(section.ignore || '0') != '1');
}

function runtimeInterfaces(env) {
	var runtime = runtimeOf(env);
	var interfaces = runtime.interfaces && runtime.interfaces.interface || runtime.interfaces || [];
	var result = {};

	if (!Array.isArray(interfaces))
		interfaces = [];

	interfaces.forEach(function(item) {
		if (item && item.interface)
			result[item.interface] = item;
	});

	return result;
}

function netmaskPrefix(netmask) {
	var bits = 0;
	var valid = true;

	String(netmask || '').split('.').forEach(function(part) {
		var value = Number(part);
		var binary;

		if (!Number.isInteger(value) || value < 0 || value > 255) {
			valid = false;
			return;
		}

		binary = value.toString(2).padStart(8, '0');
		bits += (binary.match(/1/g) || []).length;
	});

	return valid && String(netmask || '').split('.').length == 4 ? bits : null;
}

function interfaceAddress(cfg, runtime) {
	var addresses = runtime && (runtime['ipv4-address'] || runtime.ipv4_address) || [];
	var address;
	var prefix;

	if (Array.isArray(addresses) && addresses[0]) {
		address = addresses[0].address || addresses[0].ipaddr;
		prefix = addresses[0].mask !== undefined ? addresses[0].mask : addresses[0].prefix;

		if (address)
			return prefix !== undefined ? '%s/%s'.format(address, prefix) : String(address);
	}

	if (!cfg.ipaddr)
		return _('No IPv4 address');

	prefix = netmaskPrefix(cfg.netmask);
	return prefix !== null ? '%s/%s'.format(cfg.ipaddr, prefix) : String(cfg.ipaddr);
}

function allSectionNames(env) {
	var uci = uciOf(env);
	var names = {};

	[ 'network', 'dhcp', 'firewall', 'wireless' ].forEach(function(key) {
		Object.keys(uciValues(uci[key] || {})).forEach(function(name) {
			names[name] = true;
		});
	});

	return names;
}

function uniqueSectionName(env, base) {
	var names = allSectionNames(env);
	var candidate = base;
	var i;

	if (!names[candidate])
		return candidate;

	for (i = 2; i < 100; i++) {
		candidate = base + i;

		if (!names[candidate])
			return candidate;
	}

	return base + String(Date.now()).slice(-4);
}

function nextNatAddress(env) {
	var used = {};
	var octet = 15;

	networkSections(env).forEach(function(section) {
		var match = String(section.cfg.ipaddr || '').match(/^192\.168\.(\d+)\.1$/);

		if (match)
			used[Number(match[1])] = true;
	});

	while (used[octet] && octet < 254)
		octet++;

	return '192.168.%d.1'.format(octet);
}

function networkType(name, cfg, dhcp) {
	if (cfg.airui_type == 'nat')
		return _('NAT');

	if (cfg.airui_type == 'vlan_bridge')
		return _('VLAN Bridge');

	if (cfg.proto == 'dhcp')
		return _('DHCP Client');

	if (cfg.proto == 'none')
		return _('VLAN Bridge');

	if (cfg.proto == 'static' && dhcpEnabled(dhcp) && (/nat/i.test(name) || /^br-nat/i.test(cfg.device || '')))
		return _('NAT');

	if (cfg.proto == 'static')
		return _('Static');

	return cfg.proto ? cfg.proto.toUpperCase() : _('Interface');
}

function detected(env, key, fallback) {
	var d = dataOf(env).detected || {};
	return t(d[key], fallback);
}

function uplinkFirewallZone(env) {
	var zone = detected(env, 'uplink_firewall_zone', 'lan');
	var hasWan = false;

	networkSections(env).forEach(function(section) {
		if (section.name == 'wan')
			hasWan = true;
	});

	if (zone == 'wan' && !hasWan)
		return 'lan';

	return zone;
}

function statCard(label, value, note) {
	return E('div', { 'class': 'wireless-ref-radio' }, [
		E('div', { 'class': 'wireless-ref-title' }, [
			E('span', { 'class': 'wireless-ref-icon' }),
			E('div', {}, [
				E('small', {}, label),
				E('h3', {}, value),
				E('p', {}, note || '')
			])
		])
	]);
}

function option(value, label, selected) {
	return E('option', {
		'value': value,
		'selected': String(value) == String(selected) ? 'selected' : null
	}, label);
}

function field(label, node, attrs) {
	attrs = Object.assign({ 'class': 'wireless-ref-field' }, attrs || {});

	return E('label', attrs, [
		E('span', {}, label),
		node
	]);
}

function input(name, value, placeholder) {
	return E('input', {
		'name': name,
		'type': 'text',
		'value': value || '',
		'placeholder': placeholder || ''
	});
}

function derivedField(label, key, attrs) {
	attrs = Object.assign({ 'class': 'interface-derived-field' }, attrs || {});

	return E('div', attrs, [
		E('small', {}, label),
		E('strong', { 'data-derived': key }, '-')
	]);
}

function checkbox(name, checked, label, note) {
	return E('label', { 'class': 'wireless-ref-check' }, [
		E('input', { 'name': name, 'type': 'checkbox', 'checked': checked ? 'checked' : null }),
		E('span', {}, [
			E('b', {}, label),
			E('small', {}, note || '')
		])
	]);
}

function formValue(form, name, fallback) {
	var el = form.querySelector('[name="%s"]'.format(name));
	return el ? el.value : fallback;
}

function formChecked(form, name) {
	var el = form.querySelector('[name="%s"]'.format(name));
	return !!(el && el.checked);
}

function collectPayload(form) {
	var type = formValue(form, 'type', 'nat');
	var name = formValue(form, 'name', type == 'nat' ? 'nat_network' : 'vlan100');
	var bridge = formValue(form, 'bridge_name', type == 'nat' ? 'br-nat' : 'br-' + name);
	var firewallZone = formValue(form, 'firewall_zone', type == 'nat' ? 'nat' : name);
	var dhcpStart = Number(formValue(form, 'dhcp_start', '100'));
	var dhcpEnd = Number(formValue(form, 'dhcp_end', formValue(form, 'dhcp_limit', '199')));
	var dhcpLimit = Math.max(1, dhcpEnd - dhcpStart + 1);
	var dhcpEnabled = type == 'nat';
	var secureNat = type == 'nat';
	var payload = {
		type: type,
		name: name,
		vlan_id: type == 'vlan_bridge' ? Number(formValue(form, 'vlan_id', '100')) : null,
		parent_device: type == 'vlan_bridge' ? formValue(form, 'parent_device', 'wan') : null,
		bridge_name: bridge,
		proto: type == 'nat' ? 'static' : 'none',
		ipaddr: type == 'nat' ? formValue(form, 'ipaddr', '192.168.15.1') : null,
		netmask: type == 'nat' ? formValue(form, 'netmask', '255.255.255.0') : null,
		dhcp: type == 'nat' ? {
			enabled: dhcpEnabled,
			start: dhcpStart,
			limit: dhcpLimit,
			end: dhcpEnd,
			leasetime: formValue(form, 'leasetime', '12h')
		} : { enabled: false },
		firewall: {
			enabled: true,
			zone: firewallZone,
			input: type == 'nat' && secureNat ? 'REJECT' : formValue(form, 'firewall_input', type == 'nat' ? 'REJECT' : 'REJECT'),
			output: 'ACCEPT',
			forward: 'REJECT',
			allow_dhcp: type == 'nat' && secureNat,
			allow_dns: type == 'nat' && secureNat,
			forward_to: type == 'nat' ? formValue(form, 'forward_to', uplinkFirewallZone(lastConfig)) : null,
			enable_masquerade_on_uplink: type == 'nat'
		},
		dry_run: true
	};

	return payload;
}

function callWithPayload(fn, payload) {
	return fn(
		payload.type,
		payload.name,
		payload.vlan_id,
		payload.parent_device,
		payload.bridge_name,
		payload.proto,
		payload.ipaddr,
		payload.netmask,
		payload.dhcp,
		payload.firewall,
		payload.dry_run
	);
}

function waitForInterfaceApplyResult(attempts) {
	attempts = attempts == null ? 24 : attempts;

	return applyStatus.refresh().then(function(status) {
		if (status.state == 'failure')
			throw new Error(status.message || _('Network apply failed.'));

		if (status.state == 'rollback') {
			applyStatus.show('rollback', status.message || _('Network apply was rolled back.'));
			throw new Error(status.message || _('Network apply was rolled back.'));
		}

		if (status.state == 'applying' && status.terminal !== true && attempts > 0) {
			applyStatus.show('applying', status.message || _('Network apply is still running...'));
			return new Promise(function(resolve) {
				window.setTimeout(resolve, 1000);
			}).then(function() {
				return waitForInterfaceApplyResult(attempts - 1);
			});
		}

		if (status.state == 'applying')
			throw new Error(_('Network apply is still running. Refresh this page in a moment to confirm the result.'));

		return status;
	});
}

function applyInterfacesRequest() {
	if (cloudManaged)
		return cloudManagedError();

	var apply = safeCall(function() {
		return callInterfaceApply(true, true, [ 'network', 'dnsmasq', 'firewall' ], 90);
	}).then(function(result) {
		if (!result || result.ok === false)
			throw new Error(backendError(result, _('Apply failed.')));

		return waitForInterfaceApplyResult();
	}).then(function() {
		applyStatus.show('success', _('Network interface configuration applied.'));
		ui.addNotification(null, E('p', {}, _('Network interface configuration applied.')), 'info');
		window.setTimeout(function() {
			window.location.reload();
		}, 3500);
	}).catch(function(err) {
		if (isTimeoutError(err)) {
			applyStatus.show('applying', _('Apply request timed out. Checking backend status...'));

			return waitForInterfaceApplyResult().then(function() {
				applyStatus.show('success', _('Network interface configuration applied.'));
				ui.addNotification(null, E('p', {}, _('Network interface configuration applied.')), 'info');
				window.setTimeout(function() {
					window.location.reload();
				}, 3500);
			}).catch(function(statusErr) {
				var message = statusErr && statusErr.message ?
					statusErr.message :
					_('Network apply timed out. The configuration may not have been applied.');

				applyStatus.show('failure', message);
				ui.addNotification(null, E('p', {}, message), 'danger');
				throw statusErr || new Error(message);
			});
		}

		ui.addNotification(null, E('p', {}, err.message || err), 'danger');
		throw err;
	});

	return apply;
}

function applyInterfaces() {
	return applyStatus.run('interface-apply', _('Network interface configuration'), applyInterfacesRequest);
}

function saveInterfaceRequest(form, mode, apply) {
	if (cloudManaged)
		return cloudManagedError();

	var payload = collectPayload(form);
	var method = mode == 'set' ? callInterfaceSet : callInterfaceAdd;

	return callWithPayload(method, Object.assign({}, payload, { dry_run: true })).then(function(dry) {
		if (!dry || dry.ok === false)
			throw new Error(backendError(dry, _('Validation failed.')));

		return callWithPayload(method, Object.assign({}, payload, { dry_run: false }));
	}).then(function(result) {
		if (!result || result.ok === false)
			throw new Error(backendError(result, _('Save failed.')));

		ui.hideModal();
		if (apply)
			return applyInterfaces();

		ui.addNotification(null, E('p', {}, _('Interface configuration saved.')), 'info');
		return Promise.resolve(result);
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, err.message || err), 'danger');
		throw err;
	});
}

function saveInterface(form, mode, apply) {
	return applyStatus.run('interface-save', _('Network interface configuration'), function() {
		return saveInterfaceRequest(form, mode, apply);
	}, form);
}

function editInterfaceModal(item, dhcp) {
	if (cloudManaged)
		return cloudManagedError();

	var type = item.cfg.airui_type;
	var device = networkConfigSection(lastConfig, item.name + '_dev');
	var start = Number(dhcp.start || 100);
	var end = start + Number(dhcp.limit || 100) - 1;
	var isNat = type == 'nat';
	var bridge = item.cfg.device || item.cfg.ifname || ('br-' + item.name.replace(/_/g, '-'));
	var parent = device.ifname || detected(lastConfig, 'uplink_device', 'wan');
	var vlanId = device.vid || '100';
	var form = E('form', { 'class': 'wireless-add-form interface-add-form' }, [
		E('div', { 'class': 'wireless-ref-form' }, [
			derivedField(_('Type'), 'type'),
			derivedField(_('Name'), 'name'),
			E('input', { 'name': 'type', 'type': 'hidden', 'value': type }),
			E('input', { 'name': 'name', 'type': 'hidden', 'value': item.name }),
			E('input', { 'name': 'bridge_name', 'type': 'hidden', 'value': bridge }),
			E('input', { 'name': 'firewall_zone', 'type': 'hidden', 'value': item.name }),
			E('input', { 'name': 'forward_to', 'type': 'hidden', 'value': uplinkFirewallZone(lastConfig) }),
			E('input', { 'name': 'leasetime', 'type': 'hidden', 'value': dhcp.leasetime || '12h' }),
			field(_('IPv4 address'), E('input', { 'name': 'ipaddr', 'type': 'text', 'value': item.cfg.ipaddr || '', 'required': 'required', 'inputmode': 'decimal' }), { 'data-nat-only': '1', 'style': isNat ? '' : 'display:none' }),
			field(_('Subnet mask'), E('input', { 'name': 'netmask', 'type': 'text', 'value': item.cfg.netmask || '255.255.255.0', 'required': 'required', 'inputmode': 'decimal' }), { 'data-nat-only': '1', 'style': isNat ? '' : 'display:none' }),
			field(_('DHCP start'), E('input', { 'name': 'dhcp_start', 'type': 'number', 'min': '1', 'max': '254', 'value': String(start), 'required': 'required' }), { 'data-nat-only': '1', 'style': isNat ? '' : 'display:none' }),
			field(_('DHCP end'), E('input', { 'name': 'dhcp_end', 'type': 'number', 'min': '1', 'max': '254', 'value': String(end), 'required': 'required' }), { 'data-nat-only': '1', 'style': isNat ? '' : 'display:none' }),
			field(_('VLAN ID'), E('input', { 'name': 'vlan_id', 'type': 'number', 'min': '1', 'max': '4094', 'value': String(vlanId), 'required': 'required' }), { 'data-vlan-only': '1', 'style': isNat ? 'display:none' : '' }),
			E('input', { 'name': 'parent_device', 'type': 'hidden', 'value': parent })
		]),
		E('div', { 'class': 'wireless-add-actions air-standard-actions' }, [
			E('button', { 'class': 'wireless-save', 'type': 'button', 'click': ui.hideModal }, _('Cancel')),
			E('button', { 'class': 'wireless-save', 'type': 'button', 'click': function() { saveInterface(form, 'set', false); } }, _('Save')),
			E('button', { 'class': 'wireless-save is-primary', 'type': 'button', 'click': function() { saveInterface(form, 'set', true); } }, _('Save & Apply'))
		])
	]);

	ui.showModal(_('Edit Interface'), [
		form,
		E('p', { 'class': 'wireless-add-note' }, _('Changes are validated before the interface and dependent services are updated.'))
	], 'interface-add-modal');

	form.querySelector('[data-derived="type"]').textContent = isNat ? _('NAT Network') : _('VLAN Bridge');
	form.querySelector('[data-derived="name"]').textContent = item.name;
}

function addInterfaceModal(type) {
	if (cloudManaged)
		return cloudManagedError();

	var initialNatName = uniqueSectionName(lastConfig, 'nat_network');
	var initialNatAddress = nextNatAddress(lastConfig);

	function setValue(name, value) {
		var el = form.querySelector('[name="%s"]'.format(name));

		if (el)
			el.value = value;
	}

	function setDerived(name, value) {
		form.querySelectorAll('[data-derived="%s"]'.format(name)).forEach(function(el) {
			el.textContent = value;
		});
	}

	function vlanId() {
		return formValue(form, 'vlan_id', '100').replace(/\D/g, '') || '100';
	}

	function applyVlanDerived() {
		var id = vlanId();
		var name = 'vlan' + id;
		var bridge = 'br-vlan' + id;
		var parent = detected(lastConfig, 'uplink_device', 'wan');

		setValue('name', name);
		setValue('bridge_name', bridge);
		setValue('firewall_zone', name);
		setValue('parent_device', parent);
		setDerived('name', name);
		setDerived('bridge_name', bridge);
		setDerived('firewall_zone', name);
		setDerived('parent_device', parent);
	}

	function applyNatDerived() {
		var name = formValue(form, 'name', initialNatName).trim() || initialNatName;
		var bridge = 'br-' + name.replace(/_/g, '-');
		var zone = name;
		var forward = uplinkFirewallZone(lastConfig);

		setValue('bridge_name', bridge);
		setValue('firewall_zone', zone);
		setValue('leasetime', '12h');
		setValue('forward_to', forward);
		setDerived('bridge_name', bridge);
		setDerived('firewall_zone', zone);
		setDerived('forward_to', forward);
		setDerived('leasetime', '12h');
		setDerived('policy', _('DHCP and DNS allowed, client input rejected'));
	}

	function applyTypeDefaults(isNat) {
		if (isNat) {
			initialNatName = uniqueSectionName(lastConfig, 'nat_network');
			initialNatAddress = nextNatAddress(lastConfig);
			setValue('name', initialNatName);
			setValue('ipaddr', initialNatAddress);
			setValue('netmask', '255.255.255.0');
			setValue('dhcp_start', '100');
			setValue('dhcp_end', '199');
			applyNatDerived();
		}
		else {
			applyVlanDerived();
		}
	}

	var form = E('form', { 'class': 'wireless-add-form interface-add-form' }, [
		E('div', { 'class': 'wireless-ref-form' }, [
			field(_('Type'), E('select', { 'name': 'type', 'change': function(ev) {
				var isNat = ev.target.value == 'nat';
				form.querySelectorAll('[data-nat-only]').forEach(function(el) { el.style.display = isNat ? '' : 'none'; });
				form.querySelectorAll('[data-vlan-only]').forEach(function(el) { el.style.display = isNat ? 'none' : ''; });
				applyTypeDefaults(isNat);
			} }, [
				option('nat', _('NAT Network'), type || 'nat'),
				option('vlan_bridge', _('VLAN Bridge'), type || 'nat')
			])),
			field(_('Name'), E('input', {
				'name': 'name',
				'type': 'text',
				'value': type == 'vlan_bridge' ? 'vlan100' : initialNatName,
				'pattern': '[a-z0-9_]+',
				'maxlength': '32',
				'required': 'required',
				'input': applyNatDerived
			}), { 'data-nat-only': '1' }),
			E('input', { 'name': 'name', 'type': 'hidden', 'value': type == 'vlan_bridge' ? 'vlan100' : initialNatName }),
			E('input', { 'name': 'bridge_name', 'type': 'hidden', 'value': type == 'vlan_bridge' ? 'br-vlan100' : 'br-' + initialNatName.replace(/_/g, '-') }),
			E('input', { 'name': 'firewall_zone', 'type': 'hidden', 'value': type == 'vlan_bridge' ? 'vlan100' : initialNatName }),
			E('input', { 'name': 'parent_device', 'type': 'hidden', 'value': detected(lastConfig, 'uplink_device', 'wan') }),
			field(_('VLAN ID'), E('input', { 'name': 'vlan_id', 'type': 'number', 'min': '1', 'max': '4094', 'value': '100', 'required': 'required', 'input': applyVlanDerived }), { 'data-vlan-only': '1' }),
			field(_('IPv4 address'), E('input', { 'name': 'ipaddr', 'type': 'text', 'value': initialNatAddress, 'placeholder': initialNatAddress, 'required': 'required', 'inputmode': 'decimal' }), { 'data-nat-only': '1' }),
			field(_('Subnet mask'), E('input', { 'name': 'netmask', 'type': 'text', 'value': '255.255.255.0', 'placeholder': '255.255.255.0', 'required': 'required', 'inputmode': 'decimal' }), { 'data-nat-only': '1' }),
			field(_('DHCP start'), E('input', { 'name': 'dhcp_start', 'type': 'number', 'min': '1', 'max': '254', 'value': '100', 'required': 'required' }), { 'data-nat-only': '1' }),
			field(_('DHCP end'), E('input', { 'name': 'dhcp_end', 'type': 'number', 'min': '1', 'max': '254', 'value': '199', 'required': 'required' }), { 'data-nat-only': '1' })
		]),
		E('div', { 'class': 'wireless-add-actions air-standard-actions' }, [
			E('button', { 'class': 'wireless-save', 'type': 'button', 'click': ui.hideModal }, _('Cancel')),
			E('button', { 'class': 'wireless-save', 'type': 'button', 'click': function() { saveInterface(form, 'add', false); } }, _('Save')),
			E('button', { 'class': 'wireless-save is-primary', 'type': 'button', 'click': function() { saveInterface(form, 'add', true); } }, _('Save & Apply'))
		])
	]);

	ui.showModal(_('Add Interface'), [
		form,
		E('p', { 'class': 'wireless-add-note' }, _('The interface will be validated before it is applied.'))
	], 'interface-add-modal');

	form.querySelector('[name="type"]').dispatchEvent(new Event('change'));
}

function deleteInterface(name) {
	if (cloudManaged)
		return cloudManagedError();

	return actionDialog.run('delete-interface-' + name, {
		title: _('Delete interface'),
		message: _('Delete interface %s? Its network configuration will be removed and connectivity may be interrupted.').format(name),
		confirmLabel: _('Delete interface'),
		danger: true,
		progressHeading: _('Deleting interface'),
		progressMessage: _('Validating the request and applying the network configuration.')
	}, function() { return callInterfaceDelete(name, false, true).then(function(dry) {
		if (!dry || dry.ok === false)
			throw new Error(backendError(dry, _('Delete validation failed.')));

		return callInterfaceDelete(name, false, false);
	}).then(function(result) {
		if (!result || result.ok === false)
			throw new Error(backendError(result, _('Delete failed.')));

		return applyInterfaces();
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, err.message || err), 'danger');
		throw err;
	}); });
}

function updatedTime() {
	return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function refreshInterfaces() {
	var button = pageRefs.refreshButton;
	var status = pageRefs.refreshStatus;

	if (pageRefs.refreshing)
		return Promise.resolve();

	pageRefs.refreshing = true;
	button.disabled = true;
	button.textContent = _('Refreshing...');
	status.className = 'air-page-updated';
	status.textContent = _('Loading current interface data...');

	return safeCall(callInterfaceConfig).then(function(config) {
		var nextTable;

		if (!config || config.ok === false)
			throw new Error(backendError(config, _('Interface refresh failed.')));

		lastConfig = config;
		nextTable = table(config);
		pageRefs.table.parentNode.replaceChild(nextTable, pageRefs.table);
		pageRefs.table = nextTable;
		status.className = 'air-page-updated status-good';
		status.textContent = _('Updated at %s').format(updatedTime());
	}).catch(function(err) {
		status.className = 'air-page-updated error';
		status.textContent = _('Update failed - showing previous data');
		ui.addNotification(null, E('p', {}, err.message || err), 'danger');
	}).finally(function() {
		pageRefs.refreshing = false;
		button.disabled = false;
		button.textContent = _('Refresh');
	});
}

function table(env) {
	var sections = networkSections(env);
	var runtime = runtimeInterfaces(env);

	return E('section', { 'class': 'wireless-ref-panel interface-panel' }, [
		E('div', { 'class': 'wireless-panel-head' }, [
			E('div', {}, [
				E('h2', {}, _('Configured Interfaces')),
				E('p', {}, _('%d network interfaces discovered.').format(sections.length))
			]),
			E('div', { 'class': 'wireless-ref-panel-actions' }, [
				E('span', { 'class': 'wireless-ref-count' }, String(sections.length)),
				E('button', { 'class': 'wireless-save is-primary', 'type': 'button', 'disabled': cloudManaged, 'title': cloudManaged ? _('Managed by AirPro Cloud') : '', 'click': function() { addInterfaceModal('nat'); } }, _('+ Add Interface'))
			])
		]),
		E('div', { 'class': 'air-settings-table interface-table' }, [
			E('div', { 'class': 'air-setting-row is-head' }, [
				E('span', {}, _('Name')),
				E('span', {}, _('Type')),
				E('span', {}, _('Address')),
				E('span', {}, _('DHCP Server')),
				E('span', {}, _('Manage'))
			])
		].concat(
			sections.map(function(item) {
				var dhcp = dhcpSection(env, item.name);
				var enabled = dhcpEnabled(dhcp);
				var removable = String(item.cfg.airui_managed || '') == '1';
				var addr = interfaceAddress(item.cfg, runtime[item.name]);

				return E('div', { 'class': 'air-setting-row' }, [
					E('strong', {}, item.name),
					E('span', {}, networkType(item.name, item.cfg, dhcp)),
					E('span', {}, addr),
					E('span', { 'class': enabled ? 'air-status-pill is-positive' : 'air-status-pill is-disabled' }, enabled ? _('Enabled') : _('Disabled')),
					E('span', { 'class': 'interface-actions' }, removable && !cloudManaged ? [
						E('button', {
							'class': 'wireless-ref-icon-button wireless-icon-edit',
							'type': 'button',
							'title': _('Edit interface'),
							'aria-label': _('Edit interface %s').format(item.name),
							'click': function() { editInterfaceModal(item, dhcp); }
						}),
						E('button', {
							'class': 'wireless-ref-icon-button wireless-icon-trash is-danger',
							'type': 'button',
							'title': _('Delete interface'),
							'aria-label': _('Delete interface %s').format(item.name),
							'click': function() { deleteInterface(item.name); }
						})
					] : [
						E('span', {
							'class': 'wireless-status-pill',
							'title': _('System-managed interface'),
							'style': 'min-width:0;max-width:100%;white-space:nowrap;padding:.2rem .4rem'
						}, cloudManaged ? _('Cloud managed') : _('Protected'))
					])
				]);
			})
		))
	]);
}

function backendUnavailable(env) {
	return E('div', { 'class': 'airdash wireless-page wireless-ref-console' }, [
		E('section', { 'class': 'wireless-ref-head' }, [
			E('div', { 'class': 'wireless-ref-title-block' }, [
				E('h1', {}, _('Network Interfaces')),
				E('p', {}, _('Create VLAN bridge and NAT client interfaces.'))
			])
		]),
		E('section', { 'class': 'wireless-ref-section' }, [
			E('h2', {}, _('Feature not ready')),
			E('p', {}, backendError(env, _('The AirUI interface backend is unavailable.')))
		])
	]);
}

return view.extend({
	load: function() {
		return safeCall(callHealth).then(function(health) {
			if (!health || health.ok === false)
				return [ health, null ];

			return Promise.all([
				Promise.resolve(health),
				safeCall(callInterfaceConfig),
				safeCall(callControllerStatus)
			]);
		});
	},

	render: function(data) {
		var health = data[0];
		var config = data[1];
		var controller = data[2];
		var refreshButton;
		var refreshStatus;
		var tableNode;

		if (!health || health.ok === false)
			return backendUnavailable(health);

		if (!config || config.ok === false)
			return backendUnavailable(config);

		lastConfig = config;
		cloudManaged = !!(controller && controller.ok === true && controller.data &&
			controller.data.mode == 'cloud');
		refreshButton = E('button', {
			'class': 'wireless-save is-primary air-refresh',
			'type': 'button',
			'click': refreshInterfaces
		}, _('Refresh'));
		refreshStatus = E('small', {
			'class': 'air-page-updated status-good',
			'role': 'status',
			'aria-live': 'polite'
		}, _('Updated at %s').format(updatedTime()));
		tableNode = table(config);
		pageRefs = {
			refreshButton: refreshButton,
			refreshStatus: refreshStatus,
			table: tableNode,
			refreshing: false
		};

		return E('div', { 'class': 'airdash wireless-page wireless-ref-console interface-page' + (cloudManaged ? ' is-cloud-managed' : '') }, [
			E('section', { 'class': 'wireless-ref-head' }, [
				E('div', { 'class': 'wireless-ref-title-block' }, [
					E('span', { 'class': 'air-page-eyebrow' }, _('Network')),
					E('h1', {}, _('Network Interfaces')),
					E('p', {}, _('Create VLAN bridge networks, NAT client gateways, DHCP service and SSID mappings.'))
				]),
				E('div', { 'class': 'wireless-ref-toolbar' }, [
					refreshButton,
					refreshStatus
				])
			]),
			cloudManaged ? cloudManagedNotice() : null,
			tableNode
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
