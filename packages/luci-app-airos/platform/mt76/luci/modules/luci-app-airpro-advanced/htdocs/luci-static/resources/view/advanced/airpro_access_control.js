'use strict';
'require view';

function toggle(label, checked, hint) {
	return E('label', { 'class': 'ac-toggle' }, [
		E('input', { 'type': 'checkbox', 'checked': checked ? 'checked' : null }),
		E('span', {}),
		E('div', {}, [
			E('strong', {}, label),
			hint ? E('small', {}, hint) : E([])
		])
	]);
}

function select(label, values, selected) {
	return E('label', { 'class': 'ac-field' }, [
		E('span', {}, label),
		E('select', {}, values.map(function(v) {
			return E('option', { 'selected': v == selected ? 'selected' : null }, v);
		}))
	]);
}

function input(label, value, unit) {
	return E('label', { 'class': 'ac-field' }, [
		E('span', {}, label),
		E('div', { 'class': 'ac-input-unit' }, [
			E('input', { 'type': 'text', 'value': value || '' }),
			unit ? E('em', {}, unit) : E([])
		])
	]);
}

function table(title, headers, rows, action) {
	return E('div', { 'class': 'ac-panel' }, [
		E('div', { 'class': 'ac-panel-head' }, [
			E('div', {}, [
				E('h3', {}, title),
				E('small', {}, _('Static preview - backend not wired'))
			]),
			action ? E('button', { 'class': 'cbi-button cbi-button-add' }, action) : E([])
		]),
		E('table', { 'class': 'table ac-table' }, [
			E('tr', { 'class': 'tr table-titles' }, headers.map(function(h) {
				return E('th', { 'class': 'th' }, h);
			}))
		].concat(rows.map(function(row) {
			return E('tr', { 'class': 'tr' }, row.map(function(cell) {
				return E('td', { 'class': 'td' }, cell);
			}));
		})))
	]);
}

function section(title, desc, body) {
	return E('section', { 'class': 'ac-section' }, [
		E('div', { 'class': 'ac-section-title' }, [
			E('h3', {}, title),
			E('p', {}, desc)
		]),
		body
	]);
}

return view.extend({
	render: function() {
		return E('div', { 'class': 'air-page access-page' }, [
			E('h2', {}, _('Access Control')),
			E('div', { 'class': 'ac-hero' }, [
				E('div', {}, [
					E('span', {}, _('Static UI Prototype')),
					E('h3', {}, _('Client and SSID policy controls')),
					E('p', {}, _('Preview how access-control features will look and operate. Save/Apply buttons are visual only until backend wiring is added.'))
				]),
				E('div', { 'class': 'ac-hero-actions' }, [
					E('button', { 'class': 'cbi-button' }, _('Discard')),
					E('button', { 'class': 'cbi-button cbi-button-apply' }, _('Save & Apply'))
				])
			]),

			E('div', { 'class': 'ac-layout' }, [
				E('nav', { 'class': 'ac-tabs' }, [
					E('a', { 'href': '#ac-policy' }, _('Policy')),
					E('a', { 'href': '#ac-filtering' }, _('Filtering')),
					E('a', { 'href': '#ac-limits' }, _('Limits')),
					E('a', { 'href': '#ac-sessions' }, _('Sessions')),
					E('a', { 'href': '#ac-detection' }, _('Detection'))
				]),

				E('div', { 'class': 'ac-workspace' }, [
					section(_('SSID Policy'), _('Control isolation, whitelisting and per-SSID access behavior.'), E('div', { 'class': 'ac-grid', 'id': 'ac-policy' }, [
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Isolation Controls')),
									E('small', {}, _('Protect users from each other and from local VLAN traffic'))
								])
							]),
							toggle(_('Full Client Isolation'), true, _('Deny client-to-client traffic on the same SSID')),
							toggle(_('Deny inter-user bridging'), true, _('Block L2 bridging between wireless users')),
							toggle(_('Deny intra-VLAN traffic'), false, _('Prevent users from reaching peers in the same VLAN')),
							toggle(_('Force DHCP'), true, _('Only allow clients with DHCP-assigned addresses'))
						]),
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Policy Target')),
									E('small', {}, _('Choose where this policy applies'))
								])
							]),
							select(_('SSID'), [ 'AIR-2G-8BE9', 'AIR-5G-8BEA', 'Guest-WiFi', 'All SSIDs' ], 'AIR-2G-8BE9'),
							select(_('User group'), [ 'All users', 'Guests', 'Employees', 'Blocked devices' ], 'All users'),
							select(_('Default action'), [ 'Allow except blocked', 'Block except whitelisted', 'Monitor only' ], 'Allow except blocked')
						])
					])),

					section(_('URL & Application Filtering / Whitelisting'), _('Preview allow/block policies for destinations and applications.'), E('div', { 'id': 'ac-filtering' }, [
						table(_('URL / Domain Rules'),
							[ _('Type'), _('Match'), _('Action'), _('Applied To'), _('Schedule') ],
							[
								[ _('Domain'), 'youtube.com', _('Block'), 'Guest-WiFi', _('Office hours') ],
								[ _('Category'), _('Adult content'), _('Block'), _('All SSIDs'), _('Always') ],
								[ _('Domain'), 'airpro.local', _('Whitelist'), _('All users'), _('Always') ]
							],
							_('Add Rule')),
						table(_('Application Rules'),
							[ _('Application'), _('Category'), _('Action'), _('Bandwidth'), _('Applied To') ],
							[
								[ 'Netflix', _('Streaming'), _('Throttle'), '4 Mbps', 'Guest-WiFi' ],
								[ 'BitTorrent', _('P2P'), _('Block'), '-', 'All SSIDs' ],
								[ 'Zoom', _('Collaboration'), _('Prioritize'), _('High'), 'Employees' ]
							],
							_('Add App'))
					])),

					section(_('Bandwidth and Capacity Limits'), _('Set per-SSID, per-user and per-radio access limits.'), E('div', { 'class': 'ac-grid', 'id': 'ac-limits' }, [
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Bandwidth Restriction')),
									E('small', {}, _('Static per-SSID/per-user limit preview'))
								])
							]),
							select(_('Limit mode'), [ _('Per SSID'), _('Per user'), _('Per SSID + per user') ], _('Per SSID + per user')),
							input(_('SSID download'), '50', 'Mbps'),
							input(_('SSID upload'), '20', 'Mbps'),
							input(_('Per-user download'), '8', 'Mbps'),
							input(_('Per-user upload'), '4', 'Mbps')
						]),
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Maximum Clients per Radio')),
									E('small', {}, _('Protect airtime and preserve capacity'))
								])
							]),
							input(_('2.4 GHz radio limit'), '128', _('clients')),
							input(_('5 GHz radio limit'), '256', _('clients')),
							input(_('6 GHz radio limit'), '256', _('clients')),
							toggle(_('Reject new clients after limit'), true, _('Existing sessions continue until disconnected'))
						])
					])),

					section(_('L2 / L3 / L4 Filtering'), _('Build MAC, IP and port based rules.'), E('div', {}, [
						table(_('L2 MAC Filtering'),
							[ _('MAC Address'), _('Device Label'), _('Action'), _('SSID'), _('Status') ],
							[
								[ 'D6:52:26:93:F2:F0', 'Test phone', _('Allow'), 'AIR-2G-8BE9', _('Enabled') ],
								[ 'AA:BB:CC:DD:EE:FF', 'Unknown device', _('Block'), _('All SSIDs'), _('Enabled') ]
							],
							_('Add MAC')),
						table(_('L3 / L4 IP and Port Filtering'),
							[ _('Source'), _('Destination'), _('Protocol'), _('Port'), _('Action') ],
							[
								[ 'Guest-WiFi', '192.168.1.0/24', 'TCP', '22, 80, 443', _('Block') ],
								[ 'Employees', '10.10.0.0/16', 'Any', '*', _('Allow') ]
							],
							_('Add Rule'))
					])),

					section(_('OS Restriction and Session Control'), _('Limit access by detected OS, schedule and active session state.'), E('div', { 'class': 'ac-grid', 'id': 'ac-sessions' }, [
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('OS Restriction')),
									E('small', {}, _('Preview device fingerprint policy'))
								])
							]),
							toggle(_('Allow Android'), true),
							toggle(_('Allow iOS'), true),
							toggle(_('Allow Windows'), true),
							toggle(_('Block unknown OS'), false, _('Move unknown devices to quarantine policy'))
						]),
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Internet Freeze / Session Control')),
									E('small', {}, _('Pause access per SSID or user'))
								])
							]),
							select(_('Freeze target'), [ _('Guest-WiFi'), _('AIR-2G-8BE9'), _('Selected user'), _('All SSIDs') ], _('Guest-WiFi')),
							select(_('Freeze mode'), [ _('Now'), _('Scheduled'), _('Recurring') ], _('Scheduled')),
							input(_('Start time'), '22:00', ''),
							input(_('End time'), '06:00', ''),
							toggle(_('Terminate active sessions'), true)
						])
					])),

					section(_('Random MAC Detection'), _('Detect private/randomized MAC addresses and choose enforcement behavior.'), E('div', { 'class': 'ac-grid', 'id': 'ac-detection' }, [
						E('div', { 'class': 'ac-panel' }, [
							E('div', { 'class': 'ac-panel-head' }, [
								E('div', {}, [
									E('h3', {}, _('Detection Policy')),
									E('small', {}, _('Static preview of randomized MAC workflow'))
								])
							]),
							toggle(_('Detect random MAC addresses'), true),
							select(_('Action'), [ _('Notify only'), _('Move to guest VLAN'), _('Block until approved') ], _('Notify only')),
							toggle(_('Show warning in client list'), true),
							toggle(_('Require re-authentication'), false)
						]),
						table(_('Recent Detections'),
							[ _('Client'), _('MAC'), _('SSID'), _('Detection'), _('Action') ],
							[
								[ 'Unknown Android', 'DA:7A:9B:11:42:90', 'Guest-WiFi', _('Randomized'), _('Notify') ],
								[ 'iPhone', 'F2:19:AA:08:34:10', 'AIR-2G-8BE9', _('Private Address'), _('Notify') ]
							],
							null)
					]))
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
