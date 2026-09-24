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

var callControllerStatus = rpc.declare({
	object: 'airui.mode',
	method: 'controller_status',
	expect: { '': {} }
});

var callControllerSet = rpc.declare({
	object: 'airui.mode',
	method: 'controller_set',
	params: [ 'mode', 'cloud_url', 'broker_host', 'broker_port', 'interval', 'dry_run' ],
	expect: { '': {} }
});

var callWanManagementConfig = rpc.declare({
	object: 'airui.system',
	method: 'wan_management_config',
	expect: { '': {} }
});

var callWanManagementSet = rpc.declare({
	object: 'airui.system',
	method: 'wan_management_set',
	params: [ 'proto', 'ipaddr', 'netmask', 'gateway', 'dns', 'vlan_id', 'dry_run' ],
	expect: { '': {} }
});

var callMaintenanceConfig = rpc.declare({
	object: 'airui.maintenance',
	method: 'config',
	expect: { '': {} }
});

var callMaintenanceLogs = rpc.declare({
	object: 'airui.maintenance',
	method: 'logs',
	expect: { '': {} }
});

var callMaintenanceSyslogGet = rpc.declare({
	object: 'airui.maintenance',
	method: 'syslog_get',
	expect: { '': {} }
});

var callMaintenanceSyslogSet = rpc.declare({
	object: 'airui.maintenance',
	method: 'syslog_set',
	params: [ 'enabled', 'server', 'port', 'protocol', 'dry_run' ],
	expect: { '': {} }
});

var callMaintenanceReboot = rpc.declare({
	object: 'airui.maintenance',
	method: 'reboot',
	params: [ 'dry_run' ],
	expect: { '': {} }
});

var callMaintenanceFactoryReset = rpc.declare({
	object: 'airui.maintenance',
	method: 'factory_reset',
	params: [ 'dry_run', 'confirm' ],
	expect: { '': {} }
});

var callMaintenanceDeviceSet = rpc.declare({
	object: 'airui.maintenance',
	method: 'device_management_set',
	params: [ 'hostname', 'zonename', 'timezone', 'dry_run' ],
	expect: { '': {} }
});

var callFirmwareValidate = rpc.declare({
	object: 'airui.maintenance',
	method: 'firmware_validate',
	params: [ 'path' ],
	expect: { '': {} }
});

var callFirmwareUpgrade = rpc.declare({
	object: 'airui.maintenance',
	method: 'firmware_upgrade',
	params: [ 'path', 'keep_settings', 'force', 'dry_run', 'confirm' ],
	expect: { '': {} }
});

var callFileWrite = rpc.declare({
	object: 'file',
	method: 'write',
	params: [ 'path', 'data', 'append', 'mode', 'base64' ],
	expect: { '': {} }
});

var callFileRemove = rpc.declare({
	object: 'file',
	method: 'remove',
	params: [ 'path' ],
	expect: { '': {} }
});

function item(label, value) {
	return E('div', { 'class': 'air-setting-item' }, [
		E('span', {}, label),
		E('strong', {}, value)
	]);
}

function selectMaintenanceTab(ev) {
	var link = ev.currentTarget;
	var nav = link ? link.closest('.air-maintenance-nav') : null;
	var page = nav ? nav.closest('.air-system-maintenance') : null;
	var targetId = link && link.getAttribute('href') ? link.getAttribute('href').replace(/^#/, '') : '';

	if (!nav || !page || !targetId)
		return;

	ev.preventDefault();

	Array.prototype.forEach.call(nav.querySelectorAll('a'), function(item) {
		var active = item === link;
		item.classList.toggle('is-active', active);
		item.setAttribute('aria-selected', active ? 'true' : 'false');
		item.setAttribute('tabindex', active ? '0' : '-1');
	});

	Array.prototype.forEach.call(page.querySelectorAll('.air-maintenance-group'), function(panel) {
		var active = panel.id === targetId;
		panel.classList.toggle('is-active', active);
		panel.hidden = !active;
	});
}

function navigateMaintenanceTabs(ev) {
	var keys = [ 'ArrowLeft', 'ArrowRight', 'Home', 'End' ];

	if (keys.indexOf(ev.key) < 0)
		return;

	var links = Array.prototype.slice.call(ev.currentTarget.querySelectorAll('a'));
	var current = links.indexOf(document.activeElement);
	var next = current;

	if (ev.key == 'Home')
		next = 0;
	else if (ev.key == 'End')
		next = links.length - 1;
	else if (ev.key == 'ArrowLeft')
		next = (current - 1 + links.length) % links.length;
	else if (ev.key == 'ArrowRight')
		next = (current + 1) % links.length;

	ev.preventDefault();
	links[next].focus();
	links[next].click();
}

function field(label, value, attrs) {
	attrs = attrs || {};

	return E('label', { 'class': 'air-setting-field' }, [
		E('span', {}, label),
		E('input', Object.assign({ 'type': 'text', 'value': value || '' }, attrs))
	]);
}

function selectField(label, value, options, attrs) {
	attrs = attrs || {};

	return E('label', { 'class': 'air-setting-field' }, [
		E('span', {}, label),
		E('select', Object.assign({}, attrs), options.map(function(option) {
			return E('option', { 'value': option[0], 'selected': option[0] == value }, option[1]);
		}))
	]);
}

function toggle(label, enabled, note) {
	return E('label', { 'class': enabled ? 'air-setting-toggle is-on' : 'air-setting-toggle' }, [
		E('input', { 'type': 'checkbox', 'checked': enabled ? 'checked' : null }),
		E('span', {}, [
			E('strong', {}, label),
			note ? E('small', {}, note) : ''
		])
	]);
}

function row(cells) {
	return E('div', { 'class': 'air-setting-row' }, cells.map(function(cell, index) {
		return E('span', { 'class': index == cells.length - 1 ? 'state-pill' : '' }, cell);
	}));
}

function action(label, primary) {
	return E('button', { 'class': primary ? 'air-action is-primary' : 'air-action', 'type': 'button' }, label);
}

var pages = {
	wan_management: {
		kicker: 'Administration',
		title: 'WAN Management',
		subtitle: 'Remote management IPv4 address, gateway, DNS and access behavior.',
		summary: [['Address', '192.168.1.2'], ['Gateway', '192.168.1.1'], ['Method', 'Static'], ['Link', 'br-lan']],
		sections: [
			{ title: 'Management Configuration', type: 'fields', fields: [['Protocol', 'Static'], ['IPv4 address', '192.168.1.2'], ['Subnet mask', '255.255.255.0'], ['Gateway', '192.168.1.1'], ['Primary DNS', '192.168.1.1']] }
		]
	},
	interfaces: {
		kicker: 'Network',
		title: 'Interface',
		subtitle: 'Create and manage bridge, routed and VLAN-backed network interfaces.',
		summary: [['Interfaces', '3'], ['Bridge', 'br-lan'], ['VLANs', '2'], ['Default route', 'WAN']],
		sections: [
			{ title: 'Create Interface', type: 'fields', fields: [['Interface name', 'guest'], ['Protocol', 'Static address'], ['Device / bridge', 'br-lan.20'], ['IPv4 address', '192.168.20.1'], ['Subnet mask', '255.255.255.0'], ['VLAN ID', '20']] },
			{ title: 'Interface Options', type: 'toggles', toggles: [['Enable interface', true, 'Bring the interface up after save.'], ['Bridge mode', true, 'Attach one or more physical ports.'], ['DHCP server', true, 'Serve addresses to clients on this interface.']] },
			{ title: 'Configured Interfaces', type: 'rows', rows: [['LAN', 'br-lan', '192.168.1.2/24', 'Active'], ['WAN', 'eth0.2', 'DHCP client', 'Active'], ['Guest', 'br-lan.20', '192.168.20.1/24', 'Draft']] },
			{ title: 'Actions', type: 'actions', buttons: ['Create interface', 'Save', 'Save & Apply'] }
		]
	},
	routes: {
		kicker: 'Network',
		title: 'Routing',
		subtitle: 'Static route and gateway policy preview.',
		summary: [['Default route', '192.168.1.1'], ['LAN route', '192.168.1.0/24'], ['Metric', '0'], ['Mode', 'Bridge LAN']],
		sections: [
			{ title: 'Active Routes', type: 'rows', rows: [['0.0.0.0/0', '192.168.1.1', 'br-lan', 'Active'], ['192.168.1.0/24', 'Connected', 'br-lan', 'Active']] },
			{ title: 'Static Route Builder', type: 'fields', fields: [['Destination / prefix', '10.10.20.0/24'], ['Gateway', '192.168.1.1'], ['Interface', 'br-lan'], ['Metric', '10']] }
		]
	},
	mode: {
		kicker: 'Administration',
		title: 'Mode',
		subtitle: 'Choose local or controller-managed operation.',
		summary: [['Current mode', 'Standalone'], ['Controller', 'Available'], ['Config source', 'Local'], ['Safe apply', 'On']],
		sections: [
			{ title: 'Operating Mode', type: 'choices', choices: [['Standalone Mode', 'Active', 'Configure this AP locally.'], ['Controller Mode', 'Available', 'Adopt into central management.']] },
			{ title: 'Mode Change Notice', type: 'warning', text: 'Controller adoption may replace local wireless and security configuration.' }
		]
	},
	firewall: {
		kicker: 'Security',
		title: 'Firewall',
		subtitle: 'Gateway firewall policy preview for routed deployments.',
		summary: [['Firewall', 'Enabled'], ['Safe apply', 'On'], ['Rules', '2'], ['Logging', 'On']],
		sections: [
			{ title: 'Firewall State', type: 'toggles', toggles: [['Firewall', true, 'Apply packet filtering rules.'], ['Safe apply', true, 'Rollback if the AP becomes unreachable.'], ['Log rule changes', true, 'Track policy edits.']] },
			{ title: 'Rules', type: 'rows', rows: [['Allow management', 'TCP 443, 22', 'LAN to AP', 'Allow'], ['Block guest to LAN', 'Any', 'Guest VLAN to LAN', 'Deny']] }
		]
	},
	mac_filter: {
		kicker: 'Security',
		title: 'MAC Filter',
		subtitle: 'Allow or deny clients by MAC address.',
		summary: [['Policy', 'Deny list'], ['Entries', '1'], ['Scope', 'All SSIDs'], ['Status', 'Enabled']],
		sections: [
			{ title: 'Policy', type: 'toggles', toggles: [['MAC filtering', true, 'Filter wireless associations.'], ['Apply per SSID', true, 'Keep policy scoped to selected SSIDs.']] },
			{ title: 'Entries', type: 'rows', rows: [['D6:52:26:93:F2:F0', 'Unknown client', 'All SSIDs', 'Blocked']] }
		]
	},
	ip_filter: {
		kicker: 'Security',
		title: 'IP Filter',
		subtitle: 'Source, destination and protocol rule preview.',
		summary: [['Policy', 'Deny'], ['Rules', '1'], ['Logging', 'Off'], ['Status', 'Enabled']],
		sections: [
			{ title: 'Rule Builder', type: 'fields', fields: [['Action', 'Deny'], ['Source', '192.168.23.215'], ['Destination', 'Any'], ['Protocol / port', 'TCP 80,443']] },
			{ title: 'Rules', type: 'rows', rows: [['1', '192.168.23.215', 'Any TCP 80,443', 'Enabled']] }
		]
	},
	url_filter: {
		kicker: 'Security',
		title: 'URL Filter',
		subtitle: 'Domain allow and deny policy preview.',
		summary: [['Mode', 'Deny list'], ['Patterns', '1'], ['Schedule', 'Always'], ['Status', 'Enabled']],
		sections: [
			{ title: 'URL Filtering', type: 'toggles', toggles: [['URL filtering', true, 'Block matching domains.'], ['Whitelist mode', false, 'Allow only listed domains.']] },
			{ title: 'Patterns', type: 'rows', rows: [['*.example-social.com', 'Deny', 'Always', 'Enabled']] }
		]
	},
	access_control: {
		kicker: 'Security',
		title: 'Access Control',
		subtitle: 'Management service and trusted-source controls.',
		summary: [['HTTPS', 'Enabled'], ['SSH', 'Enabled'], ['Remote WAN', 'Disabled'], ['Timeout', '15 min']],
		sections: [
			{ title: 'Management Services', type: 'toggles', toggles: [['HTTPS', true, 'Secure web management.'], ['HTTP redirect', true, 'Redirect HTTP to HTTPS.'], ['SSH', true, 'CLI management access.'], ['SNMP', false, 'Monitoring service.']] },
			{ title: 'Allowed Sources', type: 'fields', fields: [['LAN subnet', '192.168.1.0/24'], ['Remote WAN access', 'Disabled'], ['Session timeout', '15 minutes']] }
		]
	},
	parental_control: {
		kicker: 'Security',
		title: 'Parental Control',
		subtitle: 'Schedule internet access for users or devices.',
		summary: [['Schedules', '2'], ['Freeze', 'Off'], ['Assigned devices', '0'], ['Status', 'Enabled']],
		sections: [
			{ title: 'Control State', type: 'toggles', toggles: [['Parental control', true, 'Apply schedules.'], ['Internet freeze', false, 'Pause internet now.']] },
			{ title: 'Schedules', type: 'rows', rows: [['Kids devices', 'Sun-Thu 21:00-06:30', 'Internet blocked', 'Enabled'], ['Study hours', 'Mon-Fri 18:00-20:00', 'Games and streaming blocked', 'Draft']] }
		]
	},
	device_management: {
		kicker: 'Maintenance',
		title: 'Device Management',
		subtitle: 'Identity, time, credentials and backup tools.',
		summary: [['Name', 'AirPro AX820'], ['Timezone', 'Asia/Kolkata'], ['Backup', 'Available'], ['Password', 'Configured']],
		sections: [
			{ title: 'Device Identity', type: 'fields', fields: [['Device name', 'AirPro AX820'], ['Location', 'Office AP'], ['Timezone', 'Asia/Kolkata']] },
			{ title: 'Configuration', type: 'actions', buttons: ['Download backup', 'Restore backup', 'Change password'] }
		]
	},
	system_maintenance: {
		kicker: 'Maintenance',
		title: 'System Maintenance',
		subtitle: 'Update firmware, restart the access point, or restore factory settings.',
		summary: [['Firmware', 'Ready'], ['Configuration', 'Backup recommended'], ['Reboot', 'Available'], ['Factory reset', 'Protected']],
		sections: []
	},
	reboot: {
		kicker: 'Maintenance',
		title: 'Reboot',
		subtitle: 'Restart the AP with clear impact confirmation.',
		summary: [['Estimated downtime', '90 sec'], ['Clients', 'Disconnect'], ['Config', 'Preserved'], ['Status', 'Ready']],
		sections: [
			{ title: 'Reboot Notice', type: 'warning', text: 'Wireless clients and web management will disconnect while the AP restarts.' },
			{ title: 'Action', type: 'actions', buttons: ['Reboot now', 'Schedule reboot'] }
		]
	},
	factory_default: {
		kicker: 'Maintenance',
		title: 'Factory Default',
		subtitle: 'Restore the AP to factory configuration. This is a destructive, irreversible action - review what will be erased and back up your configuration before continuing.',
		summary: [['Operation', 'Destructive'], ['Backup', 'Recommended'], ['Rollback', 'Unavailable'], ['Status', 'Locked']],
		sections: [
			{ title: 'Destructive Operation', type: 'warning', text: 'Factory default will erase wireless, IP, security and administrator settings.' },
			{ title: 'Recovery', type: 'actions', buttons: ['Download backup first', 'Reset to factory default'] }
		]
	},
	firmware_management: {
		kicker: 'Maintenance',
		title: 'Firmware Management',
		subtitle: 'Firmware version and upgrade workflow.',
		summary: [['Version', '24.10.0'], ['Kernel', '6.6.73'], ['Image check', 'Required'], ['Status', 'Up to date']],
		sections: [
			{ title: 'Installed Firmware', type: 'items', items: [['Version', 'OpenWrt 24.10.0'], ['Build', 'AirPro release'], ['Kernel', '6.6.73'], ['Platform', 'ramips/mt7621']] },
			{ title: 'Upgrade', type: 'actions', buttons: ['Choose firmware', 'Verify image', 'Upgrade firmware'] }
		]
	},
	system_logs: {
		kicker: 'Maintenance',
		title: 'System Logs',
		subtitle: 'Operational, security and administration events.',
		summary: [['Events', '3'], ['Severity', 'Info'], ['Export', 'Available'], ['Auto refresh', 'Off']],
		sections: [
			{ title: 'Recent Events', type: 'rows', rows: [['13:18:21', 'System', 'Web login successful', 'Info'], ['13:12:04', 'Wireless', 'Client associated on 5 GHz', 'Info'], ['12:58:44', 'Storage', 'Disk not mounted', 'Warning']] },
			{ title: 'Log Actions', type: 'actions', buttons: ['Refresh logs', 'Export logs', 'Clear view'] }
		]
	}
};

function key() {
	var path = L.env.requestpath || [];
	return path[path.length - 1] || 'mode';
}

function isMaintenanceKey(value) {
	return [ 'device_management', 'system_maintenance', 'reboot', 'factory_default', 'firmware_management', 'system_logs' ].indexOf(value) > -1;
}

function protoLabel(proto) {
	if (proto == 'dhcp')
		return _('DHCP client');
	if (proto == 'pppoe')
		return _('PPPoE');

	return _('Static IP');
}

function wanModeChoice(value, current, title, note) {
	return E('label', { 'class': current == value ? 'air-wan-mode is-selected' : 'air-wan-mode' }, [
		E('input', {
			'type': 'radio',
			'name': 'wan_proto',
			'value': value,
			'checked': current == value ? 'checked' : null,
			'data-wan-field': 'proto',
			'change': function(ev) { updateWanProtoFields(ev.target.closest('.air-wan-management')); }
		}),
		E('span', {}, [
			E('strong', {}, title),
			E('small', {}, note)
		])
	]);
}

function responseError(payload, fallback) {
	var errors = payload && payload.errors;

	if (errors && errors.length && errors[0] && errors[0].message)
		return errors[0].message;

	return fallback || _('Request failed');
}

function updateWanProtoFields(root) {
	var proto = root.querySelector('[data-wan-field="proto"]:checked') || root.querySelector('[data-wan-field="proto"]');
	var staticFields = root.querySelector('[data-wan-static-fields]');
	var dhcpPanel = root.querySelector('[data-wan-dhcp-panel]');
	var pppoePanel = root.querySelector('[data-wan-pppoe-panel]');
	var isDhcp = proto && proto.value == 'dhcp';
	var isPppoe = proto && proto.value == 'pppoe';

	if (staticFields)
		staticFields.style.display = isDhcp || isPppoe ? 'none' : '';

	if (dhcpPanel)
		dhcpPanel.style.display = isDhcp ? '' : 'none';

	if (pppoePanel)
		pppoePanel.style.display = isPppoe ? '' : 'none';

	Array.prototype.forEach.call(root.querySelectorAll('.air-wan-mode'), function(choice) {
		var input = choice.querySelector('input');
		choice.classList.toggle('is-selected', !!(input && input.checked));
	});
}

function modeChoice(value, current, title, status, note) {
	return E('label', { 'class': current == value ? 'air-mode-choice is-selected' : 'air-mode-choice' }, [
		E('input', {
			'type': 'radio',
			'name': 'air_mode',
			'value': value,
			'checked': current == value ? 'checked' : null,
			'data-mode-choice': value,
			'change': function(ev) { updateModePreview(ev.target.closest('.air-mode-page')); }
		}),
		E('span', {}, [
			E('strong', {}, title),
			E('small', {}, note)
		]),
		E('em', { 'class': current == value ? 'air-status-pill is-positive' : 'air-status-pill is-neutral' }, status)
	]);
}

function setText(root, selector, value) {
	var node = root ? root.querySelector(selector) : null;

	if (node)
		node.textContent = value;
}

function updateModePreview(root) {
	if (!root)
		return;

	var selectedMode = root ? root.querySelector('[data-mode-choice]:checked') : null;
	var mode = selectedMode ? selectedMode.value : 'standalone';
	var controllerBlock = root ? root.querySelector('[data-controller-section]') : null;
	var notice = root ? root.querySelector('[data-mode-notice]') : null;
	var apply = root ? root.querySelector('[data-mode-apply]') : null;
	var save = root ? root.querySelector('[data-mode-save]') : null;
	var current = root ? root.getAttribute('data-current-mode') : 'standalone';

	Array.prototype.forEach.call(root.querySelectorAll('.air-mode-choice'), function(choice) {
		var input = choice.querySelector('input');
		choice.classList.toggle('is-selected', !!(input && input.checked));
	});

	if (controllerBlock)
		controllerBlock.style.display = mode == 'cloud' ? '' : 'none';

	setText(root, '[data-mode-summary="mode"]', mode == 'cloud' ? _('Cloud Controller') : _('Standalone'));
	setText(root, '[data-mode-summary="source"]', mode == 'cloud' ? _('AirPro Cloud') : _('Local'));

	if (notice)
		notice.textContent = mode == current ?
			(mode == 'cloud' ? _('Save & Apply restarts the cloud connection with these settings.') : _('No mode change pending.')) :
			(mode == 'cloud' ? _('Cloud service will start and attempt device registration.') : _('Cloud service will stop; local management remains available.'));
	if (apply)
		apply.disabled = mode == current && mode == 'standalone';
	if (save)
		save.disabled = mode == current && mode == 'standalone';
}

function modeStateLabel(state, online) {
	if (online)
		return _('Online');
	if (state == 'registered')
		return _('Registered');
	if (state == 'discovery')
		return _('Discovering');
	if (state == 'not_registered')
		return _('Not registered');
	if (state == 'service_stopped')
		return _('Service stopped');
	return _('Not applicable');
}

function saveControllerMode(root, button) {
	if (!root || root.getAttribute('data-busy') == '1')
		return;

	var selected = root.querySelector('[data-mode-choice]:checked');
	var mode = selected ? selected.value : 'standalone';
	var cloudUrl = root.querySelector('[data-mode-field="cloud_url"]');
	var brokerHost = root.querySelector('[data-mode-field="broker_host"]');
	var brokerPort = root.querySelector('[data-mode-field="broker_port"]');
	var interval = root.querySelector('[data-mode-field="interval"]');
	button = button || root.querySelector('[data-mode-apply]');
	var values = {
		cloud_url: cloudUrl ? cloudUrl.value.trim() : '',
		broker_host: brokerHost ? brokerHost.value.trim() : '',
		broker_port: brokerPort ? Number(brokerPort.value) : 0,
		interval: interval ? Number(interval.value) : 0
	};

	root.setAttribute('data-busy', '1');
	if (button) {
		button.disabled = true;
		button.textContent = _('Applying...');
	}

	return callControllerSet(mode, values.cloud_url, values.broker_host,
		values.broker_port, values.interval, true).then(function(check) {
		if (!check || check.ok !== true)
			throw new Error(responseError(check, _('Cloud configuration validation failed.')));
		return callControllerSet(mode, values.cloud_url, values.broker_host,
			values.broker_port, values.interval, false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Operating mode could not be applied.')));
		ui.addNotification(null, E('p', {}, mode == 'cloud' ?
			_('Cloud mode enabled. Registration continues in the background.') :
			_('Standalone mode enabled.')), 'info');
		window.setTimeout(function() { window.location.reload(); }, 900);
	}).catch(function(err) {
		root.removeAttribute('data-busy');
		if (button) {
			button.disabled = false;
			button.textContent = button.hasAttribute('data-mode-save') ? _('Save') : _('Save & Apply');
		}
		ui.addNotification(null, E('p', {}, err.message || err), 'error');
	});
}

function confirmControllerMode(root, button) {
	if (!root || root.getAttribute('data-busy') == '1')
		return;

	var selected = root.querySelector('[data-mode-choice]:checked');
	var mode = selected ? selected.value : 'standalone';
	var current = root.getAttribute('data-current-mode') || 'standalone';
	var title = mode == 'cloud' ? _('Enable Cloud Controller?') : _('Switch to Standalone Mode?');
	var body;

	if (mode == 'cloud' && current == 'cloud')
		body = _('The cloud daemon will restart with the current connection settings. Telemetry and controller registration may pause briefly.');
	else if (mode == 'cloud')
		body = _('The AP will start cloud registration and may receive centrally managed wireless and security configuration.');
	else
		body = _('The cloud daemon will stop and the AP will remain available for local management.');

	if (!window.confirm('%s\n\n%s'.format(title, body)))
		return;

	return saveControllerMode(root, button);
}

function saveWanManagementRequest(apply) {
	var root = document.querySelector('.air-wan-management');

	if (!root)
		return;

	var protoField = root.querySelector('[data-wan-field="proto"]:checked') || root.querySelector('[data-wan-field="proto"]');
	var proto = protoField ? protoField.value : 'static';
	var ipaddrField = root.querySelector('[data-wan-field="ipaddr"]');
	var netmaskField = root.querySelector('[data-wan-field="netmask"]');
	var gatewayField = root.querySelector('[data-wan-field="gateway"]');
	var dnsField = root.querySelector('[data-wan-field="dns"]');
	var vlanField = root.querySelector('[data-wan-field="vlan_id"]');
	var ipaddr = ipaddrField ? ipaddrField.value.trim() : '';
	var netmask = netmaskField ? netmaskField.value.trim() : '';
	var gateway = gatewayField ? gatewayField.value.trim() : '';
	var dns = dnsField ? dnsField.value.trim() : '';
	var vlanId = vlanField ? Number(vlanField.value) : 0;

	if (proto == 'pppoe') {
		ui.addNotification(null, E('p', {}, _('PPPoE WAN management is not supported by this firmware yet. Choose DHCP client or Static IP.')), 'warning');
		return Promise.resolve();
	}

	if (!Number.isInteger(vlanId) || vlanId < 0 || vlanId > 4094) {
		ui.addNotification(null, E('p', {}, _('VLAN ID must be between 0 and 4094.')), 'danger');
		return Promise.resolve();
	}

	var save = callWanManagementSet(proto, ipaddr, netmask, gateway, dns, vlanId, true).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('WAN Management validation failed')));

		return callWanManagementSet(proto, ipaddr, netmask, gateway, dns, vlanId, false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('WAN Management configuration could not be saved')));

		ui.addNotification(null, E('p', {}, apply ?
			_('WAN Management configuration applied. The web UI may reconnect on the new address.') :
			_('WAN Management configuration saved.')), 'info');

		if (result.data && result.data.connectivity_verified !== true)
			throw new Error(_('The backend did not verify management connectivity'));
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to save WAN Management configuration: %s').format(err.message || err)), 'danger');
		throw err;
	});

	return save;
}

function saveWanManagement(apply) {
	return applyStatus.run('wan-management', _('WAN management configuration'), function() {
		return saveWanManagementRequest(apply);
	});
}

function formatUptime(seconds) {
	var value = Number(seconds || 0);
	var days = Math.floor(value / 86400);
	var hours = Math.floor((value % 86400) / 3600);
	var mins = Math.floor((value % 3600) / 60);

	if (days > 0)
		return _('%dd %dh %dm').format(days, hours, mins);

	if (hours > 0)
		return _('%dh %dm').format(hours, mins);

	return _('%dm').format(mins);
}

function formatLocalTime(epoch) {
	var value = Number(epoch || 0);
	var date;
	var pad = function(n) {
		return n < 10 ? '0' + n : String(n);
	};

	if (!value)
		return '-';

	date = new Date(value * 1000);
	return [
		date.getUTCFullYear(),
		pad(date.getUTCMonth() + 1),
		pad(date.getUTCDate())
	].join('-') + ' ' + [
		pad(date.getUTCHours()),
		pad(date.getUTCMinutes()),
		pad(date.getUTCSeconds())
	].join(':');
}

function firmwareLabel(firmware) {
	firmware = firmware || {};

	if (firmware.description && firmware.description != 'OpenWrt')
		return firmware.description;

	return [ firmware.distribution || 'OpenWrt', firmware.version || '-' ].join(' ');
}

function cardSection(title, children, wide) {
	return E('section', { 'class': wide ? 'air-card air-settings-card air-settings-wide' : 'air-card air-settings-card' }, [
		E('div', { 'class': 'air-card-head' }, [ E('h3', {}, title) ]),
		children
	]);
}

var maintenanceActionRunning = false;

function showMaintenanceDialog(options) {
	return new Promise(function(resolve) {
		var settled = false;
		var overlay;
		var finish = function(value) {
			if (settled)
				return;
			settled = true;
			overlay.remove();
			resolve(value);
		};

		overlay = E('div', { 'class': 'airui-maintenance-overlay', 'role': 'presentation' }, [
			E('section', { 'class': 'airui-maintenance-dialog', 'role': 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'airui-maintenance-dialog-title' }, [
				E('div', { 'class': 'airui-maintenance-dialog-icon', 'aria-hidden': 'true' }, '!'),
				E('div', { 'class': 'airui-maintenance-dialog-copy' }, [
					E('h2', { 'id': 'airui-maintenance-dialog-title' }, options.title),
					E('p', {}, options.body)
				]),
				E('div', { 'class': 'airui-maintenance-dialog-actions' }, [
					E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { finish(false); } }, _('Cancel')),
					E('button', { 'class': options.buttonClass || 'air-action is-primary', 'type': 'button', 'autofocus': 'autofocus', 'click': function() { finish(true); } }, options.buttonLabel)
				])
			])
		]);

		document.body.appendChild(overlay);
	});
}

function showDeviceRecoveryProgress(title, message) {
	var status = E('p', { 'class': 'airui-maintenance-progress-status' }, _('Waiting for the access point to restart...'));
	var overlay = E('div', { 'class': 'airui-maintenance-overlay airui-maintenance-progress-overlay', 'role': 'presentation' }, [
		E('section', { 'class': 'airui-maintenance-dialog airui-maintenance-progress', 'role': 'status', 'aria-live': 'assertive', 'aria-busy': 'true' }, [
			E('span', { 'class': 'airui-maintenance-spinner', 'aria-hidden': 'true' }),
			E('div', { 'class': 'airui-maintenance-dialog-copy' }, [
				E('h2', {}, title),
				E('p', {}, message),
				status
			])
		])
	]);

	document.body.appendChild(overlay);
	return { overlay: overlay, status: status };
}

function waitForDeviceRecovery(progress, offlineMessage) {
	var attempts = 0;
	var observedOffline = false;
	var finished = false;
	var probeUrl = (L.env.resource || '/luci-static/resources/').replace(/\/?$/, '/') + 'view/airui/settings_page_v25.js';
	var finish = function() {
		if (finished)
			return;
		finished = true;
		window.location.reload();
	};
	var probe = function() {
		if (finished)
			return;
		attempts++;
		progress.status.textContent = attempts == 1 ? offlineMessage :
			_('Reconnecting to the access point...');

		var request = new XMLHttpRequest();
		request.open('GET', probeUrl + '?reconnect=' + Date.now(), true);
		request.timeout = 4000;
		request.onload = function() {
			if (request.status >= 200 && request.status < 400 && observedOffline) {
				finish();
				return;
			}
			window.setTimeout(probe, 3000);
		};
		request.onerror = request.ontimeout = function() {
			observedOffline = true;
			window.setTimeout(probe, 3000);
		};
		request.send(null);
	};

	window.setTimeout(probe, 8000);
	/* If a browser keeps an in-flight request through the reboot, reload once the normal recovery window has elapsed. */
	window.setTimeout(function() {
		progress.status.textContent = _('Access point should be ready. Reloading management interface...');
		finish();
	}, 120000);
}

function confirmMaintenance(title, body, buttonLabel, buttonClass, onConfirm) {
	if (maintenanceActionRunning)
		return Promise.resolve(null);

	return showMaintenanceDialog({
		title: title,
		body: body,
		buttonLabel: buttonLabel,
		buttonClass: buttonClass
	}).then(function(approved) {
		if (!approved)
			return null;

		maintenanceActionRunning = true;
		return Promise.resolve().then(onConfirm);
	}).finally(function() {
		maintenanceActionRunning = false;
	});
}

function runReboot() {
	applyStatus.show('applying', _('Validating reboot request...'));
	return callMaintenanceReboot(true).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('Reboot validation failed')));

		applyStatus.show('applying', _('Rebooting access point...'));
		return callMaintenanceReboot(false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Reboot request failed')));

		applyStatus.show('applying', _('Reboot accepted. Waiting for the access point to return...'));
		waitForDeviceRecovery(
			showDeviceRecoveryProgress(
				_('Restarting access point'),
				_('Your web session will reconnect automatically when the device is ready. This normally takes about a minute.')
			),
			_('Waiting for the access point to go offline...')
		);
	}).catch(function(err) {
		applyStatus.show('failure', _('Reboot request failed: %s').format(err.message || err));
		ui.addNotification(null, E('p', {}, _('Unable to reboot device: %s').format(err.message || err)), 'danger');
	});
}


function requestReboot(ev) {
	if (ev)
		ev.preventDefault();

	return confirmMaintenance(
		_('Reboot device'),
		_('Wireless clients and this web session will disconnect while the access point restarts.'),
		_('Reboot now'),
		'btn cbi-button cbi-button-apply',
		runReboot
	);
}

function runFactoryReset(confirmValue) {
	applyStatus.show('applying', _('Validating factory reset request...'));
	return callMaintenanceFactoryReset(true, confirmValue).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('Factory default validation failed')));

		applyStatus.show('applying', _('Resetting access point to factory defaults...'));
		return callMaintenanceFactoryReset(false, confirmValue);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Factory default request failed')));

		applyStatus.show('applying', _('Factory reset accepted. Waiting for the access point to restart...'));
		ui.addNotification(null, E('p', {}, _('Factory default request accepted. The access point will reset and reboot.')), 'info');
	}).catch(function(err) {
		applyStatus.show('failure', _('Factory reset request failed: %s').format(err.message || err));
		ui.addNotification(null, E('p', {}, _('Unable to start factory default: %s').format(err.message || err)), 'danger');
	});
}

function requestFactoryReset(root) {
	var input = root ? root.querySelector('[data-maint-reset-confirm]') : null;
	var confirmValue = input ? input.value.trim() : '';

	if (confirmValue != 'RESET') {
		ui.addNotification(null, E('p', {}, _('Type RESET to unlock factory default.')), 'warning');
		if (input)
			input.focus();
		return;
	}

	return confirmMaintenance(
		_('Factory default'),
		_('This will erase wireless, network, security and administrator settings, then reboot the device.'),
		_('Reset device'),
		'btn cbi-button cbi-button-negative',
		function() { return runFactoryReset(confirmValue); }
	);
}

function updateFactoryResetUnlock(root) {
	var input = root ? root.querySelector('[data-maint-reset-confirm]') : null;
	var button = root ? root.querySelector('[data-maint-reset-action]') : null;

	if (!button)
		return;

	button.disabled = !(input && input.value.trim() == 'RESET');
}

function exportLogs(lines) {
	var blob = new Blob([ (lines || []).join('\n') + '\n' ], { type: 'text/plain' });
	var link = document.createElement('a');

	link.href = URL.createObjectURL(blob);
	link.download = 'airui-system-logs.txt';
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
	URL.revokeObjectURL(link.href);
}

var systemLogState = [];
var systemLogsFailed = false;
var syslogSaveRunning = false;

function renderLogLines(lines, failed) {
	if (failed)
		return [ E('p', { 'class': 'air-log-state is-error', 'role': 'alert' },
			_('System logs could not be loaded. Existing results are not shown as a valid empty log.')) ];

	if (!lines || !lines.length)
		return [ E('p', { 'class': 'air-log-state is-empty', 'role': 'status' }, _('No system log entries are currently available.')) ];

	return lines.slice().reverse().map(function(line) {
		return E('pre', {}, line);
	});
}

function setSystemLogs(root, lines, failed) {
	var panel = root ? root.querySelector('[data-system-log-list]') : null;
	var count = root ? root.querySelector('[data-system-log-count]') : null;
	var refreshed = root ? root.querySelector('[data-system-log-refreshed]') : null;

	systemLogState = lines || [];
	systemLogsFailed = !!failed;

	if (panel) {
		panel.innerHTML = '';
		renderLogLines(systemLogState, systemLogsFailed).forEach(function(node) {
			panel.appendChild(node);
		});
	}

	if (count)
		count.textContent = String(systemLogState.length);

	if (refreshed)
		refreshed.textContent = failed ? _('Refresh failed') : new Date().toLocaleTimeString();

	setText(root, '[data-system-log-hero-time]', failed ? _('Last refresh failed') : _('Updated at %s').format(new Date().toLocaleTimeString()));
}

function refreshSystemLogs(root, button) {
	if (!root || root.getAttribute('data-log-refreshing') == '1')
		return Promise.resolve();

	root.setAttribute('data-log-refreshing', '1');
	if (button) {
		button.disabled = true;
		button.setAttribute('aria-busy', 'true');
		button.textContent = _('Refreshing...');
	}

	return callMaintenanceLogs().then(function(payload) {
		if (!payload || payload.ok !== true)
			throw new Error(responseError(payload, _('Unable to refresh logs.')));

		setSystemLogs(root, payload.data ? payload.data.entries || [] : [], false);
		ui.addNotification(null, E('p', {}, _('System logs refreshed.')), 'info');
	}).catch(function(err) {
		setSystemLogs(root, systemLogState, true);
		ui.addNotification(null, E('p', {}, _('Unable to refresh logs: %s').format(err.message || err)), 'danger');
	}).finally(function() {
		root.removeAttribute('data-log-refreshing');
		if (button) {
			button.disabled = false;
			button.removeAttribute('aria-busy');
			button.textContent = _('Refresh');
		}
	});
}

function updateSyslogFields(root) {
	var enabled = root ? root.querySelector('[data-syslog-field="enabled"]') : null;

	if (!root || !enabled)
		return;

	Array.prototype.forEach.call(root.querySelectorAll('[data-syslog-dependent]'), function(input) {
		input.disabled = !enabled.checked;
	});

	var card = enabled.closest('.air-setting-toggle');
	if (card)
		card.classList.toggle('is-on', enabled.checked);
}

function validSyslogServer(value) {
	return value.length > 0 && value.length <= 253 && /^[A-Za-z0-9.\-:\[\]]+$/.test(value);
}

function saveSyslog(root, button, apply) {
	if (!root || syslogSaveRunning)
		return;

	var enabledField = root.querySelector('[data-syslog-field="enabled"]');
	var serverField = root.querySelector('[data-syslog-field="server"]');
	var portField = root.querySelector('[data-syslog-field="port"]');
	var protocolField = root.querySelector('[data-syslog-field="protocol"]');
	var enabled = !!(enabledField && enabledField.checked);
	var server = serverField ? serverField.value.trim() : '';
	var port = portField ? Number(portField.value) : 0;
	var protocol = protocolField ? protocolField.value : 'udp';

	if (enabled && !validSyslogServer(server)) {
		ui.addNotification(null, E('p', {}, _('Enter a valid syslog server address or host name.')), 'warning');
		if (serverField)
			serverField.focus();
		return;
	}
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		ui.addNotification(null, E('p', {}, _('Syslog port must be between 1 and 65535.')), 'warning');
		if (portField)
			portField.focus();
		return;
	}

	syslogSaveRunning = true;
	root.setAttribute('aria-busy', 'true');
	Array.prototype.forEach.call(root.querySelectorAll('[data-syslog-save]'), function(action) {
		action.disabled = true;
	});
	if (button) {
		button.textContent = _('Validating...');
	}

	callMaintenanceSyslogSet(enabled, server, port, protocol, true).then(function(validation) {
		if (!validation || validation.ok !== true)
			throw new Error(responseError(validation, _('Remote syslog validation failed.')));
		if (button)
			button.textContent = _('Applying...');
		return callMaintenanceSyslogSet(enabled, server, port, protocol, false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Remote syslog could not be applied.')));

		var stateSummary = root.querySelector('[data-syslog-summary="state"]');
		if (stateSummary)
			stateSummary.className = enabled ? 'air-status-pill is-positive' : 'air-status-pill is-disabled';
		setText(root, '[data-syslog-summary="state"]', enabled ? _('Enabled') : _('Disabled'));
		setText(root, '[data-syslog-summary="destination"]', enabled ? '%s:%s'.format(server, port) : '-');
		ui.addNotification(null, E('p', {}, apply ? _('Remote syslog settings applied.') : _('Remote syslog settings saved.')), 'info');
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to apply remote syslog: %s').format(err.message || err)), 'danger');
	}).finally(function() {
		syslogSaveRunning = false;
		root.removeAttribute('aria-busy');
		Array.prototype.forEach.call(root.querySelectorAll('[data-syslog-save]'), function(action) {
			action.disabled = false;
		});
		if (button) {
			button.disabled = false;
			button.textContent = apply ? _('Save & Apply') : _('Save');
		}
	});
}

var firmwareUploadPath = '/tmp/airui-firmware.bin';
var firmwareUploadMaxSize = 96 * 1024 * 1024;
var firmwareUploadState = {
	uploaded: false,
	valid: false,
	upgrading: false,
	fileName: '',
	fileSize: 0,
	validation: null
};

function firmwareOptionToggle(label, note, attrs) {
	var input;
	var control;

	attrs = attrs || {};
	input = E('input', Object.assign({ 'type': 'checkbox' }, attrs));
	control = E('div', {
		'class': input.hasAttribute('checked') ? 'air-setting-toggle is-on' : 'air-setting-toggle'
	}, [
		E('span', { 'class': 'air-setting-copy' }, [
			E('strong', {}, label),
			E('small', {}, note)
		]),
		E('label', { 'class': 'air-toggle-switch' }, [
			input,
			E('span', { 'aria-hidden': 'true' })
		])
	]);
	input.addEventListener('change', function(ev) {
		control.classList.toggle('is-on', ev.target.checked);
	});
	return control;
}

function formatBytes(value) {
	var size = Number(value || 0);
	var units = [ 'B', 'KB', 'MB', 'GB' ];
	var index = 0;

	while (size >= 1024 && index < units.length - 1) {
		size = size / 1024;
		index++;
	}

	return (index ? size.toFixed(1) : String(size)) + ' ' + units[index];
}

function fileToBase64(file) {
	return new Promise(function(resolve, reject) {
		var reader = new FileReader();

		reader.onload = function() {
			var value = String(reader.result || '');
			var comma = value.indexOf(',');

			resolve(comma > -1 ? value.slice(comma + 1) : value);
		};
		reader.onerror = function() {
			reject(reader.error || new Error(_('Unable to read firmware image.')));
		};
		reader.readAsDataURL(file);
	});
}

function setFirmwareStatus(root, text, state) {
	var status = root ? root.querySelector('[data-firmware-status]') : null;

	if (!status)
		return;

	status.textContent = text || '';
	status.className = state ? 'air-firmware-status is-' + state : 'air-firmware-status';
}

function renderValidationTests(validation) {
	var tests = validation && validation.tests ? validation.tests : {};
	var names = Object.keys(tests);

	if (!names.length)
		return E('p', { 'class': 'air-muted' }, _('No validation tests were returned.'));

	return E('div', { 'class': 'air-firmware-tests' }, names.map(function(name) {
		var passed = tests[name] === true;

		return E('div', { 'class': passed ? 'air-firmware-test is-ok' : 'air-firmware-test is-fail' }, [
			E('span', {}, passed ? '✓' : '!'),
			E('strong', {}, name.replace(/_/g, ' ')),
			E('em', {}, passed ? _('Passed') : _('Failed'))
		]);
	}));
}

function updateFirmwareValidation(root, validation) {
	var panel = root ? root.querySelector('[data-firmware-validation]') : null;
	var upgrade = root ? root.querySelector('[data-firmware-upgrade]') : null;
	var force = root ? root.querySelector('[data-firmware-force]') : null;

	firmwareUploadState.validation = validation || null;
	firmwareUploadState.valid = !!(validation && validation.valid === true);

	if (panel) {
		panel.innerHTML = '';
		if (!validation) {
			panel.appendChild(E('p', { 'class': 'air-muted' }, _('Validation results will appear here after upload.')));
		} else {
			panel.appendChild(E('div', { 'class': 'air-firmware-validation-head' }, [
				E('strong', {}, firmwareUploadState.valid ? _('Image validation passed') : _('Image validation failed')),
				E('span', { 'class': firmwareUploadState.valid ? 'state-pill success' : 'state-pill' },
					firmwareUploadState.valid ? _('Valid') : _('Not valid'))
			]));
			panel.appendChild(renderValidationTests(validation));
			if (validation.forceable)
				panel.appendChild(E('p', { 'class': 'air-muted' }, _('The platform allows this image to be forced. This can make the device unbootable.')));
		}
	}

	if (force) {
		force.disabled = !(validation && validation.forceable === true);
		if (force.disabled)
			force.checked = false;
	}

	updateFirmwareUpgradeUnlock(root);
}

function updateFirmwareUpgradeUnlock(root) {
	var upgrade = root ? root.querySelector('[data-firmware-upgrade]') : null;
	var force = root ? root.querySelector('[data-firmware-force]') : null;
	var forceAllowed = !!(firmwareUploadState.validation && firmwareUploadState.validation.forceable === true);
	var eligible = firmwareUploadState.uploaded &&
		(firmwareUploadState.valid || (forceAllowed && force && force.checked));

	if (upgrade)
		upgrade.disabled = !eligible || firmwareUploadState.upgrading;
}

function selectedFirmwareFile(root) {
	var input = root ? root.querySelector('[data-firmware-file]') : null;

	return input && input.files && input.files[0] ? input.files[0] : null;
}

function uploadFirmwareImage(root) {
	var file = selectedFirmwareFile(root);
	/* Base64 expands data by roughly one third; keep the ubus message well below 64 KiB. */
	var chunkSize = 24 * 1024;
	var offset = 0;

	if (!file) {
		ui.addNotification(null, E('p', {}, _('Choose a firmware image first.')), 'warning');
		return Promise.resolve();
	}
	if (!file.size) {
		setFirmwareStatus(root, _('The selected firmware image is empty.'), 'fail');
		return Promise.resolve();
	}
	if (file.size > firmwareUploadMaxSize) {
		setFirmwareStatus(root, _('The image is too large. Maximum upload size is %s.').format(formatBytes(firmwareUploadMaxSize)), 'fail');
		return Promise.resolve();
	}

	firmwareUploadState.uploaded = false;
	firmwareUploadState.valid = false;
	firmwareUploadState.fileName = file.name;
	firmwareUploadState.fileSize = file.size;
	updateFirmwareValidation(root, null);
	setFirmwareStatus(root, _('Preparing upload...'), 'info');

	return callFileRemove(firmwareUploadPath).catch(function() {}).then(function writeNext() {
		var chunk = file.slice(offset, Math.min(offset + chunkSize, file.size));
		var append = offset > 0;

		return fileToBase64(chunk).then(function(data) {
			return callFileWrite(firmwareUploadPath, data, append, 384, true);
		}).then(function(result) {
			if (!result || result.ok === false)
				throw new Error(responseError(result, _('Unable to write firmware image.')));

			offset += chunk.size;
			setFirmwareStatus(root, _('Uploading %s of %s...').format(formatBytes(offset), formatBytes(file.size)), 'info');

			if (offset < file.size)
				return writeNext();

			firmwareUploadState.uploaded = true;
			setFirmwareStatus(root, _('Uploaded %s (%s). Validate the image before upgrading.').format(file.name, formatBytes(file.size)), 'ok');
		});
	}).catch(function(err) {
		setFirmwareStatus(root, _('Upload failed: %s').format(err.message || err), 'fail');
		ui.addNotification(null, E('p', {}, _('Firmware upload failed: %s').format(err.message || err)), 'danger');
	});
}

function validateFirmwareImage(root) {
	if (!firmwareUploadState.uploaded) {
		ui.addNotification(null, E('p', {}, _('Upload a firmware image before validation.')), 'warning');
		return Promise.resolve();
	}

	setFirmwareStatus(root, _('Validating firmware image...'), 'info');
	return callFirmwareValidate(firmwareUploadPath).then(function(result) {
		var validation = result && result.data ? result.data.validation : null;

		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Firmware validation failed.')));

		updateFirmwareValidation(root, validation);
		setFirmwareStatus(root, validation && validation.valid ? _('Image is valid and ready to upgrade.') : _('Image is not valid for this device.'), validation && validation.valid ? 'ok' : 'fail');
	}).catch(function(err) {
		setFirmwareStatus(root, _('Validation failed: %s').format(err.message || err), 'fail');
		ui.addNotification(null, E('p', {}, _('Firmware validation failed: %s').format(err.message || err)), 'danger');
	});
}

function requestFirmwareUpgrade(root) {
	var keep = root ? root.querySelector('[data-firmware-keep]') : null;
	var force = root ? root.querySelector('[data-firmware-force]') : null;
	var keepSettings = keep ? keep.checked : true;
	var forceUpgrade = force ? force.checked : false;
	var forceAllowed = !!(firmwareUploadState.validation && firmwareUploadState.validation.forceable === true);

	if (!firmwareUploadState.uploaded || (!firmwareUploadState.valid && !(forceUpgrade && forceAllowed))) {
		ui.addNotification(null, E('p', {}, _('Validate a compatible firmware image before upgrading.')), 'warning');
		return;
	}

	return confirmMaintenance(
		_('Upgrade firmware'),
		_('This will flash the uploaded image and reboot the device. Wireless clients and this web session will disconnect.'),
		_('Upgrade now'),
		'btn cbi-button cbi-button-negative',
		function() {
			firmwareUploadState.upgrading = true;
			updateFirmwareUpgradeUnlock(root);
			setFirmwareStatus(root, _('Performing final validation...'), 'info');
			return callFirmwareUpgrade(firmwareUploadPath, keepSettings, forceUpgrade, true, 'UPGRADE').then(function(dryRun) {
				if (!dryRun || dryRun.ok !== true)
					throw new Error(responseError(dryRun, _('Firmware upgrade validation failed.')));

				return callFirmwareUpgrade(firmwareUploadPath, keepSettings, forceUpgrade, false, 'UPGRADE');
			}).then(function(result) {
				if (!result || result.ok !== true)
					throw new Error(responseError(result, _('Firmware upgrade request failed.')));

				setFirmwareStatus(root, _('Firmware upgrade started. Do not power off the device.'), 'info');
				waitForDeviceRecovery(
					showDeviceRecoveryProgress(
						_('Installing firmware'),
						_('The image is being installed. Do not power off the access point. Your web session will reconnect automatically when the upgrade is complete.')
					),
					_('Waiting for firmware installation to restart the access point...')
				);
			}).catch(function(err) {
				firmwareUploadState.upgrading = false;
				updateFirmwareUpgradeUnlock(root);
				setFirmwareStatus(root, _('Unable to start firmware upgrade: %s').format(err.message || err), 'fail');
				ui.addNotification(null, E('p', {}, _('Unable to start firmware upgrade: %s').format(err.message || err)), 'danger');
			});
		}
	);
}

var timezoneOptions = [
	[ 'UTC', 'UTC0', _('UTC') ],
	[ 'Asia/Kolkata', 'IST-5:30', _('Asia/Kolkata (UTC+05:30)') ],
	[ 'Asia/Dubai', '<+04>-4', _('Asia/Dubai (UTC+04:00)') ],
	[ 'Asia/Singapore', '<+08>-8', _('Asia/Singapore (UTC+08:00)') ],
	[ 'Asia/Shanghai', 'CST-8', _('Asia/Shanghai (UTC+08:00)') ],
	[ 'Asia/Tokyo', 'JST-9', _('Asia/Tokyo (UTC+09:00)') ],
	[ 'Europe/London', 'GMT0BST,M3.5.0/1,M10.5.0', _('Europe/London') ],
	[ 'Europe/Berlin', 'CET-1CEST,M3.5.0,M10.5.0/3', _('Europe/Berlin') ],
	[ 'America/New_York', 'EST5EDT,M3.2.0,M11.1.0', _('America/New York') ],
	[ 'America/Chicago', 'CST6CDT,M3.2.0,M11.1.0', _('America/Chicago') ],
	[ 'America/Denver', 'MST7MDT,M3.2.0,M11.1.0', _('America/Denver') ],
	[ 'America/Los_Angeles', 'PST8PDT,M3.2.0,M11.1.0', _('America/Los Angeles') ],
	[ 'Australia/Sydney', 'AEST-10AEDT,M10.1.0,M4.1.0/3', _('Australia/Sydney') ],
	[ 'Pacific/Auckland', 'NZST-12NZDT,M9.5.0,M4.1.0/3', _('Pacific/Auckland') ]
];

function timezoneSelect(value) {
	var found = false;
	var options = timezoneOptions.map(function(zone) {
		var selected = zone[0] == value;

		if (selected)
			found = true;

		return E('option', {
			'value': zone[0],
			'data-timezone': zone[1],
			'selected': selected ? 'selected' : null
		}, zone[2]);
	});

	if (!found && value)
		options.unshift(E('option', {
			'value': value,
			'data-timezone': '',
			'selected': 'selected'
		}, value));

	return E('label', { 'class': 'air-setting-field' }, [
		E('span', {}, _('Timezone')),
		E('select', { 'data-maint-field': 'zonename' }, options)
	]);
}

function selectedTimezone(root) {
	var select = root.querySelector('[data-maint-field="zonename"]');
	var selected = select ? select.options[select.selectedIndex] : null;

	return selected ? selected.getAttribute('data-timezone') || 'UTC0' : 'UTC0';
}

function saveDeviceManagementRequest() {
	var root = document.querySelector('.air-maintenance-page');
	var hostnameField = root ? root.querySelector('[data-maint-field="hostname"]') : null;
	var zoneField = root ? root.querySelector('[data-maint-field="zonename"]') : null;
	var hostname = hostnameField ? hostnameField.value.trim() : '';
	var zonename = zoneField ? zoneField.value : 'UTC';
	var timezone = root ? selectedTimezone(root) : 'UTC0';

	return callMaintenanceDeviceSet(hostname, zonename, timezone, true).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('Device settings validation failed')));

		return callMaintenanceDeviceSet(hostname, zonename, timezone, false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Device settings could not be saved')));

		ui.addNotification(null, E('p', {}, _('Device Management settings applied.')), 'info');
		setTimeout(function() { window.location.reload(); }, 800);
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to save Device Management settings: %s').format(err.message || err)), 'danger');
		throw err;
	});
}

function saveDeviceManagement() {
	return applyStatus.run('device-management', _('Device Management settings'), saveDeviceManagementRequest);
}

function renderWanManagement(page, payload) {
	var data = payload && payload.data ? payload.data : {};
	var management = data.management || {};
	var proto = management.proto || 'static';
	var ipaddr = management.ipaddr || '192.168.1.2';
	var netmask = management.netmask || '255.255.255.0';
	var gateway = management.gateway || '192.168.1.1';
	var dns = management.dns || gateway || '192.168.1.1';
	var vlanId = Number(management.vlan_id || 0);
	var interfaceName = management.interface || (vlanId ? 'wan.' + vlanId : 'wan');
	var leaseRenew = management.lease_renew || management.lease_renewal || '-';
	var leaseExpiry = management.lease_expires || management.lease_expiry || _('renews automatically');
	var connected = proto == 'dhcp' || !!ipaddr;

	return E('div', { 'class': 'air-page air-settings-page air-wan-management' }, [
		E('section', { 'class': 'air-settings-hero' }, [
			E('div', {}, [
				E('span', { 'class': 'air-settings-kicker' }, page.kicker),
				E('h1', {}, page.title),
				E('p', {}, page.subtitle)
			])
		]),
		E('section', { 'class': connected ? 'air-wan-status is-connected' : 'air-wan-status' }, [
			E('span', { 'class': 'air-wan-status-icon' }, connected ? 'OK' : '!'),
			E('strong', {}, connected ? _('Connected') : _('Not connected')),
			E('span', {}, [ _('IP'), ' ', E('b', {}, ipaddr || '-') ]),
			E('span', {}, [ _('Lease renews in'), ' ', E('b', {}, leaseRenew != '-' ? leaseRenew : leaseExpiry) ])
		]),
		E('section', { 'class': 'air-settings-summary air-wan-summary' }, [
			item(_('Interface'), interfaceName),
			item(_('Address'), ipaddr || '-'),
			item(_('Gateway'), gateway || '-'),
			item(_('DNS Servers'), dns || '-')
		]),
		E('section', { 'class': 'air-card air-settings-card air-settings-wide air-wan-config-card' }, [
			E('div', { 'class': 'air-card-head' }, [ E('h3', {}, _('Management Configuration')) ]),
			E('p', { 'class': 'air-card-subtitle' }, _('Choose how this AP obtains its management address.')),
			E('div', { 'class': 'air-wan-modes' }, [
				wanModeChoice('dhcp', proto, _('DHCP client'), _('Receives address, gateway, and DNS automatically from the upstream server.')),
				wanModeChoice('static', proto, _('Static IP'), _('Manually assign a fixed address, netmask, gateway, and DNS servers.')),
				wanModeChoice('pppoe', proto, _('PPPoE'), _('Authenticate with a username and password via a PPPoE ISP connection.'))
			]),
			E('div', { 'class': 'air-settings-form air-wan-form' }, [
				E('div', { 'class': 'air-wan-link-fields' }, [
					field(_('VLAN ID'), String(vlanId), {
						'type': 'number',
						'min': '0',
						'max': '4094',
						'step': '1',
						'data-wan-field': 'vlan_id'
					}),
					E('p', { 'class': 'air-wan-mode-note' }, _('Use 0 for untagged WAN. A VLAN ID such as 10 uses wan.10.'))
				]),
				E('div', {
					'class': 'air-wan-dhcp-panel',
					'data-wan-dhcp-panel': '1',
					'style': proto == 'dhcp' ? '' : 'display:none'
				}, [
					E('div', { 'class': 'air-wan-dhcp-lease' }, [
						E('span', {}, [ _('Current lease expires'), ' ', E('b', {}, leaseExpiry) ]),
						E('button', {
							'class': 'air-action',
							'type': 'button',
							'click': function() { window.location.reload(); }
						}, _('Renew Lease Now'))
					]),
					E('div', { 'class': 'air-settings-list' }, [
						item(_('Assigned Address'), ipaddr || '-'),
						item(_('Subnet Mask'), netmask || '-'),
						item(_('Gateway'), gateway || '-'),
						item(_('DHCP Server'), gateway || '-')
					])
				]),
				E('div', {
					'class': 'air-wan-static-fields',
					'data-wan-static-fields': '1',
					'style': proto == 'dhcp' || proto == 'pppoe' ? 'display:none' : ''
				}, [
					field(_('IPv4 address'), ipaddr, { 'data-wan-field': 'ipaddr' }),
					field(_('Subnet mask'), netmask, { 'data-wan-field': 'netmask' }),
					field(_('Gateway'), gateway, { 'data-wan-field': 'gateway' }),
					field(_('Primary DNS'), dns, { 'data-wan-field': 'dns', 'placeholder': _('Example: 192.168.1.1 8.8.8.8') })
				]),
				E('div', {
					'class': 'air-wan-pppoe-panel',
					'data-wan-pppoe-panel': '1',
					'style': proto == 'pppoe' ? '' : 'display:none'
				}, [
					field(_('Username'), '', { 'disabled': 'disabled', 'placeholder': _('Not supported in this firmware') }),
					field(_('Password'), '', { 'disabled': 'disabled', 'type': 'password', 'placeholder': _('Not supported in this firmware') }),
					E('p', { 'class': 'air-wan-mode-note' }, _('PPPoE configuration is visible for workflow planning, but this firmware backend currently supports DHCP client and Static IP only.'))
				])
			])
		]),
		E('section', { 'class': 'air-settings-applybar' }, [
			E('div', {}, [
				E('span', {}, '!'),
				E('strong', {}, _('Changing the management address can disconnect this browser session.'))
			]),
			E('div', { 'class': 'air-standard-actions' }, [
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { saveWanManagement(false); } }, _('Save')),
				E('button', { 'class': 'air-action is-primary', 'type': 'button', 'click': function() { saveWanManagement(true); } }, _('Save & Apply'))
			])
		])
	]);
}

function renderMaintenance(page, payload, selectedKey) {
	var rootKey = selectedKey || key();
	var configPayload = payload && payload.config ? payload.config : payload;
	var logsPayload = payload && payload.logs ? payload.logs : {};
	var syslogPayload = payload && payload.syslog ? payload.syslog : {};
	var data = configPayload && configPayload.data ? configPayload.data : {};
	var device = data.device || {};
	var firmware = data.firmware || {};
	var actions = data.actions || {};
	var logs = logsPayload && logsPayload.data ? logsPayload.data.entries || [] : [];
	var logsFailed = !!(payload && payload.logsError);
	var syslog = syslogPayload && syslogPayload.data ? syslogPayload.data : {};
	var syslogFailed = !!(payload && payload.syslogError);
	var summary;
	var sections;

	if (rootKey == 'system_maintenance') {
		var firmwareView = renderMaintenance(pages.firmware_management, payload, 'firmware_management');
		var rebootView = renderMaintenance(pages.reboot, payload, 'reboot');
		var factoryView = renderMaintenance(pages.factory_default, payload, 'factory_default');

		return E('div', { 'class': 'air-page air-settings-page air-maintenance-page air-system-maintenance' }, [
			E('section', { 'class': 'air-settings-hero' }, [
				E('div', {}, [
					E('span', { 'class': 'air-settings-kicker' }, page.kicker),
					E('h1', {}, page.title),
					E('p', {}, page.subtitle)
				])
			]),
			E('nav', {
				'class': 'air-maintenance-nav',
				'role': 'tablist',
				'aria-label': _('System maintenance sections'),
				'keydown': navigateMaintenanceTabs
			}, [
				E('a', { 'class': 'is-active', 'role': 'tab', 'aria-selected': 'true', 'aria-controls': 'maintenance-firmware', 'tabindex': '0', 'href': '#maintenance-firmware', 'click': selectMaintenanceTab }, _('Firmware Upgrade')),
				E('a', { 'role': 'tab', 'aria-selected': 'false', 'aria-controls': 'maintenance-reboot', 'tabindex': '-1', 'href': '#maintenance-reboot', 'click': selectMaintenanceTab }, _('Reboot')),
				E('a', { 'role': 'tab', 'aria-selected': 'false', 'aria-controls': 'maintenance-factory', 'tabindex': '-1', 'href': '#maintenance-factory', 'click': selectMaintenanceTab }, _('Factory Reset'))
			]),
			E('section', { 'id': 'maintenance-firmware', 'class': 'air-maintenance-group is-active', 'role': 'tabpanel' }, [
				E('div', { 'class': 'air-maintenance-group-head' }, [
					E('h2', {}, _('Firmware Upgrade')),
					E('p', {}, _('Validate and install a compatible system image.'))
				]),
				firmwareView.querySelector('.air-settings-grid')
			]),
			E('section', { 'id': 'maintenance-reboot', 'class': 'air-maintenance-group', 'role': 'tabpanel', 'hidden': 'hidden' }, [
				E('div', { 'class': 'air-maintenance-group-head' }, [
					E('h2', {}, _('Reboot')),
					E('p', {}, _('Restart the access point while preserving its configuration.'))
				]),
				rebootView.querySelector('.air-settings-grid')
			]),
			E('section', { 'id': 'maintenance-factory', 'class': 'air-maintenance-group is-danger', 'role': 'tabpanel', 'hidden': 'hidden' }, [
				E('div', { 'class': 'air-maintenance-group-head' }, [
					E('h2', {}, _('Factory Reset')),
					E('p', {}, _('Erase the configuration and restore the access point to factory defaults.'))
				]),
				factoryView.querySelector('.air-settings-grid')
			])
		]);
	}

	if (rootKey == 'system_logs') {
		systemLogState = logs;
		systemLogsFailed = logsFailed;
		summary = [
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Events')),
				E('strong', { 'data-system-log-count': '1' }, String(logs.length))
			]),
			item(_('Source'), _('System log')),
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Remote syslog')),
				E('strong', {
					'class': syslogFailed ? 'air-status-pill is-danger' : (syslog.enabled ? 'air-status-pill is-positive' : 'air-status-pill is-disabled'),
					'data-syslog-summary': 'state'
				}, syslogFailed ? _('Unavailable') : (syslog.enabled ? _('Enabled') : _('Disabled')))
			]),
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Destination')),
				E('strong', { 'data-syslog-summary': 'destination' }, syslog.enabled && syslog.server ? '%s:%s'.format(syslog.server, syslog.port || 514) : '-')
			])
		];
		sections = [
			cardSection(_('Recent Events'), E('div', { 'class': 'air-maintenance-log', 'data-system-log-list': '1' },
				renderLogLines(logs, logsFailed)), true),
			cardSection(_('Log Actions'), E('div', { 'class': 'air-settings-actions' }, [
				E('button', {
					'class': 'air-action is-primary',
					'type': 'button',
					'click': function(ev) {
						refreshSystemLogs(ev.currentTarget.closest('.air-maintenance-page'), ev.currentTarget);
					}
				}, _('Refresh logs')),
				E('button', {
					'class': 'air-action',
					'type': 'button',
					'disabled': !logs.length || logsFailed ? 'disabled' : null,
					'click': function() { exportLogs(systemLogState); }
				}, _('Export logs'))
			]), false),
			cardSection(_('Remote Syslog'), E('div', { 'class': 'air-syslog-config' }, [
				syslogFailed ? E('p', { 'class': 'air-log-state is-error', 'role': 'alert' },
					_('Remote syslog configuration could not be loaded.')) : '',
				E('label', { 'class': syslog.enabled ? 'air-setting-toggle is-on' : 'air-setting-toggle' }, [
					E('span', {}, [
						E('strong', {}, _('Send logs to a remote server')),
						E('small', {}, _('Forward new system messages using the selected protocol.'))
					]),
					E('span', { 'class': 'air-toggle-switch' }, [
						E('input', {
							'type': 'checkbox',
							'checked': syslog.enabled ? 'checked' : null,
							'disabled': syslogFailed ? 'disabled' : null,
							'aria-label': _('Enable remote syslog'),
							'data-syslog-field': 'enabled',
							'change': function(ev) { updateSyslogFields(ev.currentTarget.closest('.air-maintenance-page')); }
						}),
						E('span', {})
					])
				]),
				E('div', { 'class': 'air-settings-form air-syslog-fields' }, [
					field(_('Server'), syslog.server || '', {
						'data-syslog-field': 'server', 'data-syslog-dependent': '1',
						'disabled': !syslog.enabled || syslogFailed ? 'disabled' : null,
						'maxlength': '253', 'autocomplete': 'off', 'placeholder': _('Example: logs.example.com')
					}),
					field(_('Port'), String(syslog.port || 514), {
						'type': 'number', 'min': '1', 'max': '65535',
						'data-syslog-field': 'port', 'data-syslog-dependent': '1',
						'disabled': !syslog.enabled || syslogFailed ? 'disabled' : null
					}),
					selectField(_('Protocol'), syslog.protocol || 'udp', [ [ 'udp', _('UDP') ], [ 'tcp', _('TCP') ] ], {
						'data-syslog-field': 'protocol', 'data-syslog-dependent': '1',
						'disabled': !syslog.enabled || syslogFailed ? 'disabled' : null
					})
				]),
				E('div', { 'class': 'air-settings-actions air-standard-actions' }, [
					E('button', {
						'class': 'air-action', 'type': 'button',
						'click': function() { window.location.reload(); }
					}, _('Cancel')),
					E('button', {
						'class': 'air-action', 'type': 'button',
						'data-syslog-save': '1',
						'disabled': syslogFailed ? 'disabled' : null,
						'click': function(ev) { saveSyslog(ev.currentTarget.closest('.air-maintenance-page'), ev.currentTarget, false); }
					}, _('Save')),
					E('button', {
						'class': 'air-action is-primary', 'type': 'button',
						'data-syslog-save': '1',
						'disabled': syslogFailed ? 'disabled' : null,
						'click': function(ev) { saveSyslog(ev.currentTarget.closest('.air-maintenance-page'), ev.currentTarget, true); }
					}, _('Save & Apply'))
				])
			]), false)
		];
	} else if (rootKey == 'firmware_management') {
		summary = [
			item(_('Version'), firmware.version || '-'),
			item(_('Distribution'), firmware.distribution || '-'),
			item(_('Target'), firmware.target || '-'),
			item(_('Upgrade'), actions.firmware_upgrade ? _('Supported') : _('Unavailable'))
		];
		sections = [
			cardSection(_('Installed Firmware'), E('div', { 'class': 'air-firmware-installed' }, [
				E('p', { 'class': 'air-card-subtitle' }, _('Current build details, for support reference and rollback matching.')),
				E('div', { 'class': 'air-settings-list' }, [
					item(_('Description'), firmwareLabel(firmware)),
					item(_('Distribution'), firmware.distribution || '-'),
					item(_('Revision'), firmware.revision || '-'),
					item(_('Platform'), firmware.target || '-')
				])
			]), true),
			cardSection(_('Upgrade'), E('div', { 'class': 'air-firmware-flow air-firmware-upgrade' }, [
				E('p', { 'class': 'air-card-subtitle' }, _('Upload and validate a compatible image before starting an upgrade.')),
				E('div', { 'class': 'air-firmware-release' }, [
					E('strong', {}, _('Compatible image required')),
					E('span', {}, _('Target platform: %s').format(firmware.target || '-')),
					E('ul', {}, [
						E('li', {}, _('Validation must pass before the upgrade action is enabled')),
						E('li', {}, _('Keep current settings unless a clean installation is required')),
						E('li', {}, _('Do not power off the access point while the image is being written'))
					])
				]),
				E('div', { 'class': 'air-firmware-steps' }, [
					E('span', { 'class': 'is-current' }, _('1 - Choose file')),
					E('span', {}, _('2 - Validate')),
					E('span', {}, _('3 - Upgrade')),
					E('span', {}, _('4 - Reboot & verify'))
				]),
				E('label', { 'class': 'air-firmware-dropzone' }, [
					E('input', {
						'type': 'file',
						'accept': '.bin,.img,.trx,.itb,.tar,.gz,application/octet-stream',
						'data-firmware-file': '1',
						'change': function(ev) {
							var root = ev.target.closest('.air-maintenance-page');
							var file = selectedFirmwareFile(root);

							firmwareUploadState.uploaded = false;
							firmwareUploadState.valid = false;
							updateFirmwareValidation(root, null);
							setFirmwareStatus(root, file ?
								_('Selected %s (%s). Uploading...').format(file.name, formatBytes(file.size)) :
								_('Choose a firmware image to begin.'), file ? 'info' : '');

							if (file)
								uploadFirmwareImage(root);
						}
					}),
					E('span', { 'class': 'air-firmware-drop-icon' }, '^'),
					E('strong', { 'data-firmware-drop-title': '1' }, _('Drag firmware image here, or click to browse')),
					E('small', {}, _('Accepts .bin images built for ramips/mt7621 only'))
				]),
				E('div', { 'class': 'air-firmware-options' }, [
					firmwareOptionToggle(
						_('Keep current settings'),
						_('Preserve Wi-Fi, network, and admin config during upgrade. Recommended.'),
						{ 'checked': 'checked', 'data-firmware-keep': '1' }
					),
					firmwareOptionToggle(
						_('Force incompatible image'),
						_('Only enable if validation explicitly says the image is forceable. Can brick the device.'),
						{
							'disabled': 'disabled',
							'data-firmware-force': '1',
							'change': function(ev) { updateFirmwareUpgradeUnlock(ev.target.closest('.air-maintenance-page')); }
						}
					)
				]),
				E('div', { 'class': 'air-settings-actions' }, [
					E('button', {
						'class': 'air-action',
						'type': 'button',
						'click': function(ev) {
							ev.preventDefault();
							validateFirmwareImage(ev.currentTarget.closest('.air-maintenance-page'));
						}
					}, _('Validate image')),
					E('button', {
						'class': 'air-action is-danger',
						'type': 'button',
						'disabled': 'disabled',
						'data-firmware-upgrade': '1',
						'click': function(ev) {
							ev.preventDefault();
							requestFirmwareUpgrade(ev.currentTarget.closest('.air-maintenance-page'));
						}
					}, _('Upgrade firmware'))
				]),
				E('div', { 'class': 'air-firmware-status', 'data-firmware-status': '1' }, _('Choose a firmware image to begin. The upgrade button unlocks once validation passes.')),
				E('div', { 'class': 'air-firmware-validation', 'data-firmware-validation': '1' }, [
					E('p', { 'class': 'air-muted' }, _('Validation results will appear here after upload.'))
				])
			]), true)
		];
	} else if (rootKey == 'reboot') {
		summary = [
			item(_('Uptime'), formatUptime(device.uptime)),
			item(_('Clients'), _('Disconnect')),
			item(_('Configuration'), _('Preserved')),
			item(_('Status'), actions.reboot ? _('Ready') : _('Unavailable'))
		];
		sections = [
			cardSection(_('Reboot Notice'), E('div', { 'class': 'air-settings-warning' }, [
				E('p', {}, _('Wireless service and web management will be unavailable while the access point restarts.'))
			]), true),
			cardSection(_('Action'), E('div', { 'class': 'air-settings-actions' }, [
				E('button', {
					'class': 'air-action is-primary',
					'type': 'button',
					'disabled': actions.reboot ? null : 'disabled',
					'click': requestReboot
				}, _('Reboot now'))
			]), false)
		];
	} else if (rootKey == 'factory_default') {
		summary = [
			item(_('Operation'), _('Destructive')),
			item(_('Backup'), actions.backup ? _('Recommended') : _('Manual')),
			item(_('Rollback'), _('Unavailable')),
			item(_('Status'), actions.factory_reset ? _('Locked') : _('Unavailable'))
		];
		sections = [
			E('section', { 'class': 'air-card air-settings-card air-settings-wide air-factory-danger' }, [
				E('div', { 'class': 'air-factory-danger-head' }, [
					E('strong', {}, _('! This cannot be undone')),
					E('p', {}, _('Factory default erases Wi-Fi, network, security, and administrator settings and restores the device to its out-of-box state. There is no rollback for this action.'))
				]),
				E('div', { 'class': 'air-factory-erases' }, [
					E('strong', {}, _('This will permanently erase:')),
					E('div', {}, [
						E('span', {}, _('x Wi-Fi networks & passwords')),
						E('span', {}, _('x LAN / WAN network settings')),
						E('span', {}, _('x Security & firewall rules')),
						E('span', {}, _('x Administrator account & password'))
					])
				]),
				E('div', { 'class': 'air-factory-backup' }, [
					E('p', {}, [
						E('strong', {}, _('Download a backup first')),
						' ',
						E('span', {}, _('it is the only way to restore your current configuration after a reset.'))
					]),
					E('button', {
						'class': 'air-action is-success',
						'type': 'button',
						'disabled': actions.backup ? null : 'disabled',
						'click': function() { window.location.href = L.url('admin/system/flashops/backup'); }
					}, _('Open Backup'))
				]),
				E('div', { 'class': 'air-factory-confirm' }, [
					field(_('Type RESET to confirm'), '', {
						'data-maint-reset-confirm': '1',
						'autocomplete': 'off',
						'input': function(ev) { updateFactoryResetUnlock(ev.currentTarget.closest('.air-settings-page')); }
					}),
					E('small', {}, _('The button below stays disabled until this field exactly matches "RESET".')),
					E('button', {
						'class': 'air-action is-danger',
						'type': 'button',
						'disabled': 'disabled',
						'data-maint-reset-action': '1',
						'click': function(ev) {
							ev.preventDefault();
							requestFactoryReset(ev.currentTarget.closest('.air-settings-page'));
						}
					}, _('Reset to factory default'))
				])
			])
		];
	} else {
		summary = [
			item(_('Name'), device.hostname || '-'),
			item(_('Model'), device.model || '-'),
			item(_('Uptime'), formatUptime(device.uptime)),
			item(_('Local time'), formatLocalTime(device.localtime))
		];
		sections = [
			cardSection(_('Device Settings'), E('div', { 'class': 'air-settings-form air-maintenance-device-form' }, [
				field(_('Hostname'), device.hostname || '', {
					'data-maint-field': 'hostname',
					'maxlength': '63',
					'autocomplete': 'off',
					'placeholder': _('Example: Airpro')
				}),
				timezoneSelect(device.zonename || 'UTC')
			]), true),
			cardSection(_('Device Identity'), E('div', { 'class': 'air-settings-list' }, [
				item(_('Hostname'), device.hostname || '-'),
				item(_('Model'), device.model || '-'),
				item(_('Board'), device.board_name || '-'),
				item(_('System'), device.system || '-'),
				item(_('Timezone'), device.zonename || '-')
			]), false),
			cardSection(_('Firmware'), E('div', { 'class': 'air-settings-list' }, [
				item(_('Version'), firmwareLabel(firmware)),
				item(_('Kernel'), device.kernel || '-'),
				item(_('Target'), firmware.target || '-'),
				item(_('Revision'), firmware.revision || '-')
			]), false)
		];
	}

	return E('div', { 'class': 'air-page air-settings-page air-maintenance-page' }, [
		E('section', { 'class': 'air-settings-hero' }, [
			E('div', {}, [
				E('span', { 'class': 'air-settings-kicker' }, page.kicker),
				E('h1', {}, page.title),
				E('p', {}, page.subtitle)
			]),
			rootKey == 'system_logs' ? E('div', { 'class': 'status-page-actions' }, [
				E('button', {
					'class': 'status-page-refresh',
					'type': 'button',
					'click': function(ev) {
						refreshSystemLogs(ev.currentTarget.closest('.air-maintenance-page'), ev.currentTarget);
					}
				}, _('Refresh')),
				E('small', {
					'data-system-log-refreshed': '1',
					'data-system-log-hero-time': '1',
					'role': 'status'
		}, logsFailed ? _('Initial load failed') : _('Updated just now'))
			]) : ''
		]),
		E('section', { 'class': 'air-settings-summary' }, summary),
		E('div', { 'class': 'air-settings-grid' }, sections),
		rootKey == 'device_management' ? E('section', { 'class': 'air-settings-applybar' }, [
			E('div', {}, [
				E('span', {}, '!'),
				E('strong', {}, _('Hostname changes may be reflected after services reload.'))
			]),
			E('div', { 'class': 'air-standard-actions' }, [
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
				E('button', { 'class': 'air-action', 'type': 'button', 'click': saveDeviceManagement }, _('Save')),
				E('button', { 'class': 'air-action is-primary', 'type': 'button', 'click': saveDeviceManagement }, _('Save & Apply'))
			])
		]) : ''
	]);
}

function renderSection(section) {
	if (section.type == 'items')
		return E('section', { 'class': 'air-card air-settings-card' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-list' }, section.items.map(function(data) { return item(data[0], data[1]); }))
		]);

	if (section.type == 'fields')
		return E('section', { 'class': 'air-card air-settings-card' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-form' }, section.fields.map(function(data) { return field(data[0], data[1]); }))
		]);

	if (section.type == 'toggles')
		return E('section', { 'class': 'air-card air-settings-card' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-toggle-grid' }, section.toggles.map(function(data) { return toggle(data[0], data[1], data[2]); }))
		]);

	if (section.type == 'rows')
		return E('section', { 'class': 'air-card air-settings-card air-settings-wide' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-table' }, section.rows.map(row))
		]);

	if (section.type == 'choices')
		return E('section', { 'class': 'air-card air-settings-card air-settings-wide' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-choices' }, section.choices.map(function(choice, index) {
				return E('button', { 'class': index ? 'air-settings-choice' : 'air-settings-choice is-selected', 'type': 'button' }, [
					E('strong', {}, choice[0]),
					E('em', {}, choice[1]),
					E('small', {}, choice[2])
				]);
			}))
		]);

	if (section.type == 'actions')
		return E('section', { 'class': 'air-card air-settings-card' }, [
			E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
			E('div', { 'class': 'air-settings-actions' }, section.buttons.map(function(label, index) { return action(label, index == 0); }))
		]);

	return E('section', { 'class': 'air-card air-settings-card air-settings-warning' }, [
		E('div', { 'class': 'air-card-head' }, [E('h3', {}, section.title)]),
		E('p', {}, section.text)
	]);
}

function renderModePage(page, payload) {
	var config = payload && payload.data ? payload.data : {};
	var currentMode = config.mode == 'cloud' ? 'cloud' : 'standalone';
	var cloudState = modeStateLabel(config.state, config.online);
	var serialNumber = config.serial_num && !/^X+$/.test(config.serial_num) ? config.serial_num : '-';

	return E('div', {
		'class': 'air-page air-settings-page air-mode-page',
		'data-current-mode': currentMode
	}, [
		E('section', { 'class': 'air-settings-hero' }, [
			E('div', {}, [
				E('span', { 'class': 'air-settings-kicker' }, page.kicker),
				E('h1', {}, page.title),
				E('p', {}, page.subtitle)
			])
		]),
		E('section', { 'class': 'air-settings-summary air-mode-summary' }, [
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Current Mode')),
				E('strong', { 'data-mode-summary': 'mode' }, currentMode == 'cloud' ? _('Cloud Controller') : _('Standalone'))
			]),
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Cloud Status')),
				E('strong', {
					'class': currentMode == 'cloud' && config.online ? 'air-status-pill is-positive' :
						(currentMode == 'cloud' ? 'air-status-pill is-warning' : 'air-status-pill is-disabled')
				}, currentMode == 'cloud' ? cloudState : _('Disabled')),
				E('small', {}, config.service_running ? _('Cloud service running') : _('Cloud service stopped'))
			]),
		E('div', { 'class': 'air-setting-item' }, [
			E('span', {}, _('Serial Number')),
			E('strong', {}, serialNumber)
			]),
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Config Source')),
				E('strong', { 'data-mode-summary': 'source' }, currentMode == 'cloud' ? _('AirPro Cloud') : _('Local')),
				E('small', {}, currentMode == 'cloud' && config.online ? _('Connected') : _('Device configuration'))
			])
		]),
		E('section', { 'class': 'air-card air-settings-card air-settings-wide air-mode-card' }, [
			E('div', { 'class': 'air-card-head air-mode-head' }, [
				E('div', {}, [
					E('h3', {}, _('Operating Mode')),
					E('p', {}, _('Selecting a mode below previews its configuration. Nothing changes until you Save & Apply.'))
				])
			]),
			E('div', { 'class': 'air-mode-choices' }, [
				modeChoice('standalone', currentMode, _('Standalone Mode'), currentMode == 'standalone' ? _('Active') : _('Available'), _('Configure this AP locally. Cloud connectivity is disabled.')),
				modeChoice('cloud', currentMode, _('Cloud Controller'), currentMode == 'cloud' ? cloudState : _('Available'), _('Register with AirPro Cloud and receive centrally managed configuration.'))
			]),
			E('div', {
				'class': 'air-controller-section',
				'data-controller-section': '1',
				'style': currentMode == 'cloud' ? '' : 'display:none'
			}, [
				E('div', { 'class': 'air-mode-divider' }),
				E('div', { 'class': 'air-mode-subhead' }, [
					E('h4', {}, _('Cloud Connection')),
					E('p', {}, _('These values are read by air-cgwd for registration, MQTT connectivity, and telemetry reporting.'))
				]),
				E('div', {
					'class': 'air-controller-config',
					'data-cloud-panel': '1'
				}, [
					E('div', { 'class': 'air-controller-form' }, [
						field(_('Registration URL'), config.cloud_url || '', { 'data-mode-field': 'cloud_url', 'placeholder': 'https://cloud.example/api/devices' }),
						field(_('MQTT Broker'), config.broker_host || '', { 'data-mode-field': 'broker_host', 'placeholder': 'cloud.example' }),
						field(_('MQTT Port'), config.broker_port || '8883', { 'type': 'number', 'min': '1', 'max': '65535', 'data-mode-field': 'broker_port' }),
						field(_('Reporting Interval'), config.interval || '30', { 'type': 'number', 'min': '5', 'max': '3600', 'data-mode-field': 'interval' })
					]),
		E('div', { 'class': 'air-controller-status' }, [
			E('span', {}, [ _('Daemon state:'), ' ', E('b', {}, cloudState) ])
		])
				])
			])
		]),
		E('section', { 'class': 'air-mode-backup' }, [
			E('p', {}, [
				E('strong', {}, _('Recommended:')),
				' ',
				E('span', {}, _('download a config backup before switching modes - local Wi-Fi and security settings may be replaced.'))
			]),
			E('button', {
				'class': 'air-action is-success',
				'type': 'button',
				'click': function() { window.location.href = L.url('admin/system/flashops/backup'); }
			}, _('Download Backup'))
		]),
		E('section', { 'class': 'air-settings-applybar air-mode-applybar' }, [
			E('div', {}, [
				E('span', {}, '!'),
				E('strong', { 'data-mode-notice': '1' }, _('No mode change pending.'))
			]),
			E('div', { 'class': 'air-standard-actions' }, [
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
				E('button', {
					'class': 'air-action',
					'type': 'button',
					'disabled': currentMode == 'standalone' ? 'disabled' : null,
					'data-mode-save': '1',
					'click': function(ev) { confirmControllerMode(ev.currentTarget.closest('.air-mode-page'), ev.currentTarget); }
				}, _('Save')),
				E('button', {
					'class': 'air-action is-primary',
					'type': 'button',
					'disabled': currentMode == 'standalone' ? 'disabled' : null,
					'data-mode-apply': '1',
					'click': function(ev) { confirmControllerMode(ev.currentTarget.closest('.air-mode-page'), ev.currentTarget); }
				}, _('Save & Apply'))
			])
		])
	]);
}

function renderBackendUnavailable(message, page) {
	page = page || pages.wan_management;

	return E('div', { 'class': 'air-page air-settings-page' }, [
		E('section', { 'class': 'air-settings-hero' }, [
			E('div', {}, [
				E('span', { 'class': 'air-settings-kicker' }, page.kicker),
				E('h1', {}, page.title),
				E('p', {}, page.subtitle)
			])
		]),
		E('section', { 'class': 'air-card air-settings-card air-settings-wide air-settings-warning' }, [
			E('div', { 'class': 'air-card-head' }, [ E('h3', {}, _('Backend unavailable')) ]),
			E('p', {}, message || _('The AirUI system backend is not available.'))
		])
	]);
}

return view.extend({
	load: function() {
		var current = key();

		if (current != 'mode' && current != 'wan_management' && !isMaintenanceKey(current))
			return Promise.resolve({});

		return callHealth().then(function(health) {
			if (!health || health.ok !== true)
				return { unavailable: responseError(health, _('AirUI system backend is not healthy.')) };

			if (current == 'mode') {
				return callControllerStatus().then(function(status) {
					if (!status || status.ok !== true)
						return { unavailable: responseError(status, _('Unable to read controller status.')) };

					return status;
				});
			}

			if (isMaintenanceKey(current)) {
				return callMaintenanceConfig().then(function(config) {
					if (!config || config.ok !== true)
						return { unavailable: responseError(config, _('Unable to read Maintenance configuration.')) };

					if (current != 'system_logs')
						return { config: config };

					return Promise.all([
						callMaintenanceLogs().then(function(logs) {
							if (!logs || logs.ok !== true)
								return { error: responseError(logs, _('Unable to read system logs.')) };
							return { payload: logs };
						}).catch(function(err) { return { error: err.message || err }; }),
						callMaintenanceSyslogGet().then(function(syslog) {
							if (!syslog || syslog.ok !== true)
								return { error: responseError(syslog, _('Unable to read remote syslog configuration.')) };
							return { payload: syslog };
						}).catch(function(err) { return { error: err.message || err }; })
					]).then(function(results) {
						return {
							config: config,
							logs: results[0].payload || { data: { entries: [] } },
							logsError: results[0].error || null,
							syslog: results[1].payload || { data: {} },
							syslogError: results[1].error || null
						};
					});
				});
			}

			return callWanManagementConfig().then(function(config) {
				if (!config || config.ok !== true)
					return { unavailable: responseError(config, _('Unable to read WAN Management configuration.')) };

				return config;
			});
		}).catch(function(err) {
			return { unavailable: err.message || err };
		});
	},

	render: function(data) {
		var page = pages[key()] || pages.mode;

		if (key() == 'mode') {
			if (data && data.unavailable)
				return renderBackendUnavailable(data.unavailable, page);

			return renderModePage(page, data);
		}

		if (key() == 'wan_management') {
			if (data && data.unavailable)
				return renderBackendUnavailable(data.unavailable, page);

			return renderWanManagement(page, data);
		}

		if (isMaintenanceKey(key())) {
			if (data && data.unavailable)
				return renderBackendUnavailable(data.unavailable, page);

			return renderMaintenance(page, data);
		}

		return E('div', { 'class': 'air-page air-settings-page' }, [
			E('section', { 'class': 'air-settings-hero' }, [
				E('div', {}, [
					E('span', { 'class': 'air-settings-kicker' }, page.kicker),
					E('h1', {}, page.title),
					E('p', {}, page.subtitle)
				])
			]),
			E('section', { 'class': 'air-settings-summary' }, page.summary.map(function(data) { return item(data[0], data[1]); })),
			E('div', { 'class': 'air-settings-grid' }, page.sections.map(renderSection))
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
