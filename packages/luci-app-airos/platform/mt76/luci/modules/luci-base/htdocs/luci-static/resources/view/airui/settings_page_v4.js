'use strict';
'require view';
'require rpc';
'require ui';

var callHealth = rpc.declare({
	object: 'airui.system',
	method: 'health',
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
	params: [ 'proto', 'ipaddr', 'netmask', 'gateway', 'dns', 'dry_run' ],
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
	return [ 'device_management', 'reboot', 'factory_default', 'firmware_management', 'system_logs' ].indexOf(value) > -1;
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

function saveWanManagement(apply) {
	var root = document.querySelector('.air-wan-management');

	if (!root)
		return;

	var protoField = root.querySelector('[data-wan-field="proto"]:checked') || root.querySelector('[data-wan-field="proto"]');
	var proto = protoField ? protoField.value : 'static';
	var ipaddrField = root.querySelector('[data-wan-field="ipaddr"]');
	var netmaskField = root.querySelector('[data-wan-field="netmask"]');
	var gatewayField = root.querySelector('[data-wan-field="gateway"]');
	var dnsField = root.querySelector('[data-wan-field="dns"]');
	var ipaddr = ipaddrField ? ipaddrField.value.trim() : '';
	var netmask = netmaskField ? netmaskField.value.trim() : '';
	var gateway = gatewayField ? gatewayField.value.trim() : '';
	var dns = dnsField ? dnsField.value.trim() : '';

	if (proto == 'pppoe') {
		ui.addNotification(null, E('p', {}, _('PPPoE WAN management is not supported by this firmware yet. Choose DHCP client or Static IP.')), 'warning');
		return Promise.resolve();
	}

	return callWanManagementSet(proto, ipaddr, netmask, gateway, dns, true).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('WAN Management validation failed')));

		return callWanManagementSet(proto, ipaddr, netmask, gateway, dns, false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('WAN Management configuration could not be saved')));

		ui.addNotification(null, E('p', {}, apply ?
			_('WAN Management configuration applied. The web UI may reconnect on the new address.') :
			_('WAN Management configuration saved.')), 'info');
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to save WAN Management configuration: %s').format(err.message || err)), 'danger');
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

function confirmMaintenance(title, body, buttonLabel, buttonClass, onConfirm) {
	ui.showModal(title, [
		E('div', { 'class': 'air-maintenance-confirm' }, [
			E('div', { 'class': 'air-maintenance-confirm-icon' }, '!'),
			E('div', {}, [
				E('strong', {}, title),
				E('p', {}, body)
			])
		]),
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
			E('button', {
				'class': buttonClass || 'btn cbi-button cbi-button-apply',
				'click': function() {
					ui.hideModal();
					return onConfirm();
				}
			}, buttonLabel)
		])
	], 'cbi-modal air-maintenance-modal');
}

function runReboot() {
	return callMaintenanceReboot(true).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('Reboot validation failed')));

		return callMaintenanceReboot(false);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Reboot request failed')));

		ui.addNotification(null, E('p', {}, _('Reboot request accepted. The access point will restart shortly.')), 'info');
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to reboot device: %s').format(err.message || err)), 'danger');
	});
}

function requestReboot() {
	confirmMaintenance(
		_('Reboot device'),
		_('Wireless clients and this web session will disconnect while the access point restarts.'),
		_('Reboot now'),
		'btn cbi-button cbi-button-apply',
		runReboot
	);
}

function runFactoryReset(confirmValue) {
	return callMaintenanceFactoryReset(true, confirmValue).then(function(dryRun) {
		if (!dryRun || dryRun.ok !== true)
			throw new Error(responseError(dryRun, _('Factory default validation failed')));

		return callMaintenanceFactoryReset(false, confirmValue);
	}).then(function(result) {
		if (!result || result.ok !== true)
			throw new Error(responseError(result, _('Factory default request failed')));

		ui.addNotification(null, E('p', {}, _('Factory default request accepted. The access point will reset and reboot.')), 'info');
	}).catch(function(err) {
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

	confirmMaintenance(
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

function renderLogLines(lines) {
	if (!lines || !lines.length)
		return [ E('p', { 'class': 'air-muted' }, _('No log entries are available.')) ];

	return lines.slice().reverse().map(function(line) {
		return E('pre', {}, line);
	});
}

function setSystemLogs(root, lines) {
	var panel = root ? root.querySelector('[data-system-log-list]') : null;
	var count = root ? root.querySelector('[data-system-log-count]') : null;
	var refreshed = root ? root.querySelector('[data-system-log-refreshed]') : null;

	systemLogState = lines || [];

	if (panel) {
		panel.innerHTML = '';
		renderLogLines(systemLogState).forEach(function(node) {
			panel.appendChild(node);
		});
	}

	if (count)
		count.textContent = String(systemLogState.length);

	if (refreshed)
		refreshed.textContent = new Date().toLocaleTimeString();
}

function refreshSystemLogs(root, button) {
	if (button)
		button.disabled = true;

	return callMaintenanceLogs().then(function(payload) {
		var lines = payload && payload.data ? payload.data.entries || [] : [];

		if (!payload || payload.ok !== true)
			throw new Error(responseError(payload, _('Unable to refresh logs.')));

		setSystemLogs(root, lines);
		ui.addNotification(null, E('p', {}, _('System logs refreshed.')), 'info');
	}).catch(function(err) {
		ui.addNotification(null, E('p', {}, _('Unable to refresh logs: %s').format(err.message || err)), 'danger');
	}).finally(function() {
		if (button)
			button.disabled = false;
	});
}

var firmwareUploadPath = '/tmp/airui-firmware.bin';
var firmwareUploadState = {
	uploaded: false,
	valid: false,
	fileName: '',
	fileSize: 0,
	validation: null
};

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

	firmwareUploadState.validation = validation || null;
	firmwareUploadState.valid = !!(validation && validation.valid === true);

	if (panel) {
		panel.innerHTML = '';
		panel.appendChild(E('div', { 'class': 'air-firmware-validation-head' }, [
			E('strong', {}, firmwareUploadState.valid ? _('Image validation passed') : _('Image validation failed')),
			E('span', { 'class': firmwareUploadState.valid ? 'state-pill success' : 'state-pill' },
				firmwareUploadState.valid ? _('Valid') : _('Not valid'))
		]));
		panel.appendChild(renderValidationTests(validation));
		if (validation && validation.forceable)
			panel.appendChild(E('p', { 'class': 'air-muted' }, _('The image can be forced, but forcing an incompatible image can break the device.')));
	}

	if (upgrade)
		upgrade.disabled = firmwareUploadState.valid ? null : 'disabled';
}

function selectedFirmwareFile(root) {
	var input = root ? root.querySelector('[data-firmware-file]') : null;

	return input && input.files && input.files[0] ? input.files[0] : null;
}

function uploadFirmwareImage(root) {
	var file = selectedFirmwareFile(root);
	var chunkSize = 48 * 1024;
	var offset = 0;

	if (!file) {
		ui.addNotification(null, E('p', {}, _('Choose a firmware image first.')), 'warning');
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

	if (!firmwareUploadState.valid) {
		ui.addNotification(null, E('p', {}, _('Validate a compatible firmware image before upgrading.')), 'warning');
		return;
	}

	confirmMaintenance(
		_('Upgrade firmware'),
		_('This will flash the uploaded image and reboot the device. Wireless clients and this web session will disconnect.'),
		_('Upgrade now'),
		'btn cbi-button cbi-button-negative',
		function() {
			return callFirmwareUpgrade(firmwareUploadPath, keepSettings, forceUpgrade, true, 'UPGRADE').then(function(dryRun) {
				if (!dryRun || dryRun.ok !== true)
					throw new Error(responseError(dryRun, _('Firmware upgrade validation failed.')));

				return callFirmwareUpgrade(firmwareUploadPath, keepSettings, forceUpgrade, false, 'UPGRADE');
			}).then(function(result) {
				if (!result || result.ok !== true)
					throw new Error(responseError(result, _('Firmware upgrade request failed.')));

				ui.addNotification(null, E('p', {}, _('Firmware upgrade started. The device will reboot when flashing begins.')), 'info');
			}).catch(function(err) {
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

function saveDeviceManagement() {
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
	});
}

function renderWanManagement(page, payload) {
	var data = payload && payload.data ? payload.data : {};
	var management = data.management || {};
	var proto = management.proto || 'static';
	var ipaddr = management.ipaddr || '192.168.1.2';
	var netmask = management.netmask || '255.255.255.0';
	var gateway = management.gateway || '192.168.1.1';
	var dns = management.dns || gateway || '192.168.1.1';
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
			E('div', {}, [
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { saveWanManagement(false); } }, _('Save')),
				E('button', { 'class': 'air-action is-primary', 'type': 'button', 'click': function() { saveWanManagement(true); } }, _('Save & Apply'))
			])
		])
	]);
}

function renderMaintenance(page, payload) {
	var rootKey = key();
	var configPayload = payload && payload.config ? payload.config : payload;
	var logsPayload = payload && payload.logs ? payload.logs : {};
	var data = configPayload && configPayload.data ? configPayload.data : {};
	var device = data.device || {};
	var firmware = data.firmware || {};
	var actions = data.actions || {};
	var logs = logsPayload && logsPayload.data ? logsPayload.data.entries || [] : [];
	var summary;
	var sections;

	if (rootKey == 'system_logs') {
		systemLogState = logs;
		summary = [
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Events')),
				E('strong', { 'data-system-log-count': '1' }, String(logs.length))
			]),
			item(_('Source'), _('System log')),
			item(_('Export'), _('Available')),
			E('div', { 'class': 'air-setting-item' }, [
				E('span', {}, _('Last refresh')),
				E('strong', { 'data-system-log-refreshed': '1' }, _('Initial load'))
			])
		];
		sections = [
			cardSection(_('Recent Events'), E('div', { 'class': 'air-maintenance-log', 'data-system-log-list': '1' },
				renderLogLines(logs)), true),
			cardSection(_('Log Actions'), E('div', { 'class': 'air-settings-actions' }, [
				E('button', {
					'class': 'air-action is-primary',
					'type': 'button',
					'click': function(ev) {
						refreshSystemLogs(ev.target.closest('.air-maintenance-page'), ev.target);
					}
				}, _('Refresh logs')),
				E('button', {
					'class': 'air-action',
					'type': 'button',
					'click': function() { exportLogs(systemLogState); }
				}, _('Export logs'))
			]), false)
		];
	} else if (rootKey == 'firmware_management') {
		summary = [
			item(_('Version'), firmware.version || '-'),
			item(_('Distribution'), firmware.distribution || '-'),
			item(_('Target'), firmware.target || '-'),
			item(_('Upgrade'), actions.firmware_upgrade ? _('Available') : _('Available'))
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
				E('p', { 'class': 'air-card-subtitle' }, _('A new build is available for this platform.')),
				E('div', { 'class': 'air-firmware-release' }, [
					E('strong', {}, _('AIROS 1.1.0 available')),
					E('span', {}, _('released for %s, compatible with your current installation.').format(firmware.target || '-')),
					E('ul', {}, [
						E('li', {}, _('Improves Wi-Fi retry handling under high channel utilization')),
						E('li', {}, _('Fixes memory reporting on the Device Statistics page')),
						E('li', {}, _('Security patches for admin login'))
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
					E('label', { 'class': 'air-setting-toggle is-on' }, [
						E('input', { 'type': 'checkbox', 'checked': 'checked', 'data-firmware-keep': '1' }),
						E('span', {}, [
							E('strong', {}, _('Keep current settings')),
							E('small', {}, _('Preserve Wi-Fi, network, and admin config during upgrade. Recommended.'))
						])
					]),
					E('label', { 'class': 'air-setting-toggle' }, [
						E('input', { 'type': 'checkbox', 'data-firmware-force': '1' }),
						E('span', {}, [
							E('strong', {}, _('Force incompatible image')),
							E('small', {}, _('Only enable if validation explicitly says the image is forceable. Can brick the device.'))
						])
					])
				]),
				E('div', { 'class': 'air-settings-actions' }, [
					E('button', {
						'class': 'air-action',
						'type': 'button',
						'click': function(ev) { validateFirmwareImage(ev.target.closest('.air-maintenance-page')); }
					}, _('Validate image')),
					E('button', {
						'class': 'air-action is-danger',
						'type': 'button',
						'disabled': 'disabled',
						'data-firmware-upgrade': '1',
						'click': function(ev) { requestFirmwareUpgrade(ev.target.closest('.air-maintenance-page')); }
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
					}, _('Download Backup'))
				]),
				E('div', { 'class': 'air-factory-confirm' }, [
					field(_('Type RESET to confirm'), '', {
						'data-maint-reset-confirm': '1',
						'autocomplete': 'off',
						'input': function(ev) { updateFactoryResetUnlock(ev.target.closest('.air-settings-page')); }
					}),
					E('small', {}, _('The button below stays disabled until this field exactly matches "RESET".')),
					E('button', {
						'class': 'air-action is-danger',
						'type': 'button',
						'disabled': 'disabled',
						'data-maint-reset-action': '1',
						'click': function(ev) { requestFactoryReset(ev.target.closest('.air-settings-page')); }
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
			])
		]),
		E('section', { 'class': 'air-settings-summary' }, summary),
		E('div', { 'class': 'air-settings-grid' }, sections),
		rootKey == 'device_management' ? E('section', { 'class': 'air-settings-applybar' }, [
			E('div', {}, [
				E('span', {}, '!'),
				E('strong', {}, _('Hostname changes may be reflected after services reload.'))
			]),
			E('div', {}, [
				E('button', { 'class': 'air-action', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Discard Changes')),
				E('button', { 'class': 'air-action is-primary', 'type': 'button', 'click': saveDeviceManagement }, _('Apply Changes'))
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

		if (current != 'wan_management' && !isMaintenanceKey(current))
			return Promise.resolve({});

		return callHealth().then(function(health) {
			if (!health || health.ok !== true)
				return { unavailable: responseError(health, _('AirUI system backend is not healthy.')) };

			if (isMaintenanceKey(current)) {
				return callMaintenanceConfig().then(function(config) {
					if (!config || config.ok !== true)
						return { unavailable: responseError(config, _('Unable to read Maintenance configuration.')) };

					if (current != 'system_logs')
						return { config: config };

					return callMaintenanceLogs().then(function(logs) {
						if (!logs || logs.ok !== true)
							return { config: config, logs: { data: { entries: [] } } };

						return { config: config, logs: logs };
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
