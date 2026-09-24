'use strict';
'require view';

function item(label, value) {
	return E('div', { 'class': 'air-setting-item' }, [
		E('span', {}, label),
		E('strong', {}, value)
	]);
}

function field(label, value) {
	return E('label', { 'class': 'air-setting-field' }, [
		E('span', {}, label),
		E('input', { 'type': 'text', 'value': value || '', 'readonly': true })
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
	lan_ipv4: {
		kicker: 'Network',
		title: 'LAN IPv4',
		subtitle: 'Management IPv4 address, gateway, DNS and DHCP behavior.',
		summary: [['Address', '192.168.1.2'], ['Gateway', '192.168.1.1'], ['Method', 'Static'], ['Link', 'br-lan']],
		sections: [
			{ title: 'IPv4 Management', type: 'fields', fields: [['IPv4 address', '192.168.1.2'], ['Subnet mask', '255.255.255.0'], ['Gateway', '192.168.1.1'], ['Primary DNS', '192.168.1.1']] },
			{ title: 'DHCP Preview', type: 'rows', rows: [['Mode', 'Static management', 'Enabled'], ['Lease visibility', 'LAN neighbors', 'Active']] }
		]
	},
	lan_ipv6: {
		kicker: 'Network',
		title: 'LAN IPv6',
		subtitle: 'IPv6 management address and router advertisement state.',
		summary: [['IPv6', 'fe80::/64'], ['RA', 'Disabled'], ['DHCPv6', 'Disabled'], ['Interface', 'br-lan']],
		sections: [
			{ title: 'IPv6 Management', type: 'fields', fields: [['Link-local address', 'fe80::5a7b:e9ff:fe24:8beb'], ['Prefix delegation', 'Not configured'], ['Router advertisement', 'Disabled'], ['DHCPv6 service', 'Disabled']] },
			{ title: 'Status', type: 'warning', text: 'IPv6 services are shown as a preview until the backend exposes full AirUI controls.' }
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
		subtitle: 'Restore the AP to factory configuration.',
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

return view.extend({
	render: function() {
		var page = pages[key()] || pages.mode;

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
