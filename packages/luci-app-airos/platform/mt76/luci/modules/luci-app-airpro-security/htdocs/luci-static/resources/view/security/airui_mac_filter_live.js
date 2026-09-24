'use strict';
'require view';
'require ui';
'require rpc';

var selectedSection = null;

var callHealth = rpc.declare({
	object: 'airui.system',
	method: 'health',
	expect: { '': {} }
});

var callConfig = rpc.declare({
	object: 'airui.network',
	method: 'wireless_config',
	expect: { '': {} }
});

var callSet = rpc.declare({
	object: 'airui.security',
	method: 'mac_filter_set',
	params: [ 'section', 'enabled', 'mode', 'dry_run' ],
	expect: { '': {} }
});

var callEntryAdd = rpc.declare({
	object: 'airui.security',
	method: 'mac_filter_entry_add',
	params: [ 'section', 'mac', 'label', 'dry_run' ],
	expect: { '': {} }
});

var callEntryDelete = rpc.declare({
	object: 'airui.security',
	method: 'mac_filter_entry_delete',
	params: [ 'section', 'mac', 'dry_run' ],
	expect: { '': {} }
});

function icon(name) {
	return E('span', {
		'class': 'mac-icon mac-icon-' + name,
		'aria-hidden': 'true'
	});
}

function rpcError(res, fallback) {
	if (res && res.errors && res.errors[0] && res.errors[0].message)
		return res.errors[0].message;
	return fallback || _('Request failed');
}

function stat(iconName, label, value, sub, tone) {
	return E('article', { 'class': 'mac-stat ' + (tone || '') }, [
		E('span', { 'class': 'mac-stat-icon' }, icon(iconName)),
		E('div', {}, [
			E('small', {}, label),
			E('strong', {}, String(value)),
			E('em', {}, sub)
		])
	]);
}

function pill(text, tone) {
	return E('span', { 'class': 'mac-pill ' + (tone || '') }, text);
}

function actionIcon(name, title, click) {
	return E('button', {
		'class': name == 'trash' ? 'mac-icon-button is-danger' : 'mac-icon-button',
		'type': 'button',
		'title': title,
		'click': click
	}, icon(name));
}

function asArray(value) {
	if (Array.isArray(value))
		return value;

	if (value == null || value === '')
		return [];

	return [ value ];
}

function uciValue(section, name, fallback) {
	if (!section || section[name] == null || section[name] === '')
		return fallback;

	return section[name];
}

function isDisabled(section) {
	return String(uciValue(section, 'disabled', '0')) == '1';
}

function ifaceBand(section, values) {
	var device = uciValue(section, 'device', '');
	var radio = values && device ? values[device] : null;
	var band = uciValue(radio, 'band', '');

	if (band == '2g')
		return '2.4 GHz';
	if (band == '5g')
		return '5 GHz';
	if (device == 'wifi1')
		return '2.4 GHz';
	if (device == 'wifi0')
		return '5 GHz';

	return device || '-';
}

function policyMode(section) {
	var mode = String(uciValue(section, 'macfilter', 'deny')).toLowerCase();

	if (mode == 'allow')
		return 'allow';

	return 'deny';
}

function policyModeLabel(mode) {
	return mode == 'allow' ? _('Allow list') : _('Deny list');
}

function macEntries(section, mode) {
	var macs = asArray(uciValue(section, 'maclist', []));

	return macs.map(function(mac) {
		return {
			mac: String(mac),
			label: '-',
			policy: policyModeLabel(mode),
			last_seen: '-',
			state: mode == 'allow' ? _('Allowed') : _('Blocked')
		};
	});
}

function buildMacFilterData(config) {
	var values = config && config.data && config.data.uci && config.data.uci.values ? config.data.uci.values : {};
	var active = { wlan1: 1, wlan2: 1 };
	var policies = [];
	var totalEntries = 0;
	var activePolicies = 0;
	var sections = [];

	Object.keys(values).forEach(function(name) {
		var section = values[name];

		if (section && section['.type'] == 'wifi-iface')
			sections.push(name);
	});

	sections.sort(function(a, b) {
		var aa = active[a] ? 0 : 1;
		var bb = active[b] ? 0 : 1;

		if (aa != bb)
			return aa - bb;

		return a.localeCompare(b);
	});

	sections.forEach(function(name) {
		var section = values[name];
		var mode = policyMode(section);
		var filterEnabled = String(uciValue(section, 'macfilter', 'disable')).toLowerCase() != 'disable';
		var entries = macEntries(section, mode);

		totalEntries += entries.length;
		if (filterEnabled)
			activePolicies++;

		policies.push({
			section: name,
			ssid: uciValue(section, 'ssid', name),
			device: uciValue(section, 'device', ''),
			network: uciValue(section, 'network', 'lan'),
			band: ifaceBand(section, values),
			ssid_enabled: !isDisabled(section),
			filter_enabled: filterEnabled,
			mode: mode,
			mode_label: policyModeLabel(mode),
			entries_count: entries.length,
			entries: entries
		});
	});

	return {
		global: {
			enabled: activePolicies > 0,
			active_ssids: activePolicies,
			total_entries: totalEntries,
			policy_count: policies.length
		},
		policies: policies
	};
}

function policyTone(mode) {
	return mode == 'allow' ? 'is-green' : 'is-orange';
}

function bandTone(band) {
	return band == '5 GHz' ? 'is-blue' : band == 'Dual-band' ? 'is-purple' : 'is-cyan';
}

function selectSection(section) {
	selectedSection = section;
	window.location.hash = encodeURIComponent(section);
	window.location.reload();
}

function notifyError(res, fallback) {
	ui.addNotification(null, E('p', {}, rpcError(res, fallback)), 'danger');
}

function policyBySection(policies, section) {
	for (var i = 0; i < policies.length; i++)
		if (policies[i].section == section)
			return policies[i];

	return null;
}

function checkedPolicies(policies) {
	var selected = [];
	var boxes = document.querySelectorAll('.mac-policy-select:checked');

	for (var i = 0; i < boxes.length; i++)
		if (boxes[i].value)
			selected.push(boxes[i].value);

	if (!selected.length && selectedSection)
		selected.push(selectedSection);

	return selected.filter(function(section, index) {
		return selected.indexOf(section) == index && policyBySection(policies, section);
	});
}

function applyPolicy(section, enabled, mode) {
	return callSet(section, enabled, mode, true).then(function(dry) {
		if (!dry || dry.ok === false) {
			notifyError(dry, _('MAC filter policy did not validate'));
			return Promise.reject(new Error(rpcError(dry)));
		}

		return callSet(section, enabled, mode, false).then(function(res) {
			if (!res || res.ok === false) {
				notifyError(res, _('MAC filter policy was not saved'));
				return Promise.reject(new Error(rpcError(res)));
			}
		});
	});
}

function setPolicy(section, enabled, mode) {
	return applyPolicy(section, enabled, mode).then(function() {
		window.location.reload();
	}).catch(function(err) {
		notifyError(null, err.message);
	});
}

function setPolicies(policies, sections, enabled, mode) {
	var chain = Promise.resolve();

	if (!sections.length) {
		ui.addNotification(null, E('p', {}, _('Select one or more SSIDs first.')), 'warning');
		return;
	}

	for (var i = 0; i < sections.length; i++) {
		(function(section) {
			chain = chain.then(function() {
				var policy = policyBySection(policies, section);
				return applyPolicy(section,
					enabled == null ? policy.filter_enabled : enabled,
					mode || policy.mode || 'deny');
			});
		})(sections[i]);
	}

	return chain.then(function() {
		window.location.reload();
	}).catch(function(err) {
		notifyError(null, err.message);
	});
}

function addEntries(sections, mac, label) {
	var chain = Promise.resolve();

	for (var i = 0; i < sections.length; i++) {
		(function(section) {
			chain = chain.then(function() {
				return callEntryAdd(section, mac, label, true).then(function(dry) {
					if (!dry || dry.ok === false)
						return Promise.reject(new Error(rpcError(dry, _('MAC entry did not validate'))));

					return callEntryAdd(section, mac, label, false).then(function(res) {
						if (!res || res.ok === false)
							return Promise.reject(new Error(rpcError(res, _('MAC entry was not added'))));
					});
				});
			});
		})(sections[i]);
	}

	return chain;
}

function addEntry(policies, sections) {
	var macInput = E('input', {
		'class': 'cbi-input-text',
		'type': 'text',
		'placeholder': '00:11:22:33:44:55'
	});
	var labelInput = E('input', {
		'class': 'cbi-input-text',
		'type': 'text',
		'placeholder': _('Optional device label')
	});
	var targets = E('div', { 'class': 'mac-target-grid' });

	for (var i = 0; i < policies.length; i++) {
		var policy = policies[i];
		var checked = sections.indexOf(policy.section) > -1;

		targets.appendChild(E('label', { 'class': 'mac-target-option' }, [
			E('input', {
				'type': 'checkbox',
				'value': policy.section,
				'checked': checked ? 'checked' : null
			}),
			E('span', {}, [
				E('strong', {}, policy.ssid || policy.section),
				E('em', {}, '%s · %s'.format(policy.band || '-', policy.network || '-'))
			])
		]));
	}

	ui.showModal(_('Add MAC Entry'), [
		E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'mac-modal-grid' }, [
				E('label', {}, [
					E('span', {}, _('MAC address')),
					macInput
				]),
				E('label', {}, [
					E('span', {}, _('Device / label')),
					labelInput
				])
			]),
			E('h4', {}, _('Apply to SSIDs')),
			E('p', { 'class': 'mac-modal-help' }, _('Select every SSID that should receive this MAC entry.')),
			targets
		]),
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')),
			' ',
			E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'click': function() {
					var mac = (macInput.value || '').trim();
					var label = (labelInput.value || '').trim();
					var selected = [];
					var boxes = targets.querySelectorAll('input[type="checkbox"]:checked');

					for (var i = 0; i < boxes.length; i++)
						selected.push(boxes[i].value);

					if (!selected.length) {
						ui.addNotification(null, E('p', {}, _('Select at least one SSID.')), 'warning');
						return;
					}

					return addEntries(selected, mac, label).then(function() {
						window.location.reload();
					}).catch(function(err) {
						notifyError(null, err.message);
					});
				}
			}, _('Add MAC to selected SSIDs'))
		])
	]);
}

function deleteEntry(section, mac) {
	if (!confirm(_('Delete MAC entry %s?').format(mac)))
		return;

	return callEntryDelete(section, mac, true).then(function(dry) {
		if (!dry || dry.ok === false) {
			notifyError(dry, _('MAC entry did not validate'));
			return;
		}

		return callEntryDelete(section, mac, false).then(function(res) {
			if (!res || res.ok === false) {
				notifyError(res, _('MAC entry was not deleted'));
				return;
			}

			window.location.reload();
		});
	}).catch(function(err) {
		notifyError(null, err.message);
	});
}

function policyRow(policy, selected) {
	var status = policy.filter_enabled ? _('Enabled') : _('Disabled');
	var rowToggle = E('input', {
		'type': 'checkbox',
		'checked': policy.filter_enabled ? 'checked' : null
	});
	var rowMode = E('select', { 'class': 'mac-row-select' }, [
		E('option', { 'value': 'deny', 'selected': policy.mode != 'allow' ? 'selected' : null }, _('Deny list')),
		E('option', { 'value': 'allow', 'selected': policy.mode == 'allow' ? 'selected' : null }, _('Allow list'))
	]);

	rowToggle.addEventListener('change', function() {
		setPolicy(policy.section, rowToggle.checked, rowMode.value);
	});
	rowMode.addEventListener('change', function() {
		setPolicy(policy.section, rowToggle.checked, rowMode.value);
	});

	return E('div', { 'class': selected ? 'mac-policy-row is-selected' : 'mac-policy-row' }, [
		E('span', {}, E('input', {
			'class': 'mac-policy-select',
			'type': 'checkbox',
			'value': policy.section,
			'checked': selected ? 'checked' : null
		})),
		E('span', { 'class': 'mac-ssid-name' }, [
			icon('wifi'),
			E('strong', {}, policy.ssid || policy.section)
		]),
		E('span', {}, pill(policy.band || '-', bandTone(policy.band))),
		E('span', { 'class': 'mac-state-line' }, [ E('b'), status ]),
		E('span', {}, E('label', { 'class': 'mac-row-switch' }, [
			E('span', {}, _('MAC filter')),
			E('label', { 'class': 'mac-switch' }, [
				rowToggle,
				E('span')
			])
		])),
		E('span', {}, rowMode),
		E('span', { 'class': 'tech' }, String(policy.entries_count || 0)),
		E('span', {}, E('button', {
			'class': 'mac-manage',
			'type': 'button',
			'click': function() { selectSection(policy.section); }
		}, [ _('View entries'), icon('chev') ]))
	]);
}

function entryRow(section, entry) {
	var blocked = entry.state == 'Blocked';

	return E('div', { 'class': 'mac-entry-row' }, [
		E('span', { 'class': 'tech' }, entry.mac || '-'),
		E('span', {}, entry.label || '-'),
		E('span', {}, entry.policy || '-'),
		E('span', {}, entry.last_seen || '-'),
		E('span', {}, pill(entry.state || '-', blocked ? 'is-red' : 'is-green')),
		E('span', { 'class': 'mac-entry-actions' }, [
			actionIcon('trash', _('Delete'), function() {
				deleteEntry(section, entry.mac);
			})
		])
	]);
}

function emptyRow(message) {
	return E('div', { 'class': 'mac-entry-row' }, [
		E('span', { 'style': 'grid-column: 1 / -1;' }, message)
	]);
}

function policyRows(policies, selected) {
	var selectAll = E('input', {
		'type': 'checkbox',
		'title': _('Select all SSIDs')
	});

	selectAll.addEventListener('change', function() {
		var boxes = document.querySelectorAll('.mac-policy-select');
		for (var i = 0; i < boxes.length; i++)
			boxes[i].checked = selectAll.checked;
	});

	var rows = [
		E('div', { 'class': 'mac-policy-head' }, [
			E('span', {}, selectAll),
			E('span', {}, _('SSID Name')),
			E('span', {}, _('Band')),
			E('span', {}, _('SSID')),
			E('span', {}, _('MAC Filter')),
			E('span', {}, _('Mode')),
			E('span', {}, _('Entries')),
			E('span', {}, _('Actions'))
		])
	];

	if (!policies.length) {
		rows.push(emptyRow(_('No SSID policies were found.')));
		return rows;
	}

	for (var i = 0; i < policies.length; i++)
		rows.push(policyRow(policies[i], selected && policies[i].section == selected.section));

	return rows;
}

function entryRows(selected) {
	var entries = selected ? asArray(selected.entries) : [];
	var rows = [
		E('div', { 'class': 'mac-entry-head' }, [
			E('span', {}, _('MAC Address')),
			E('span', {}, _('Device / Label')),
			E('span', {}, _('Policy')),
			E('span', {}, _('Last Seen')),
			E('span', {}, _('State')),
			E('span', {}, _('Actions'))
		])
	];

	if (!entries.length) {
		rows.push(emptyRow(_('No MAC entries are configured for this SSID.')));
		return rows;
	}

	for (var i = 0; i < entries.length; i++)
		rows.push(entryRow(selected.section, entries[i]));

	return rows;
}

function renderUnavailable(message) {
	return E('div', { 'class': 'mac-filter-page' }, [
		E('section', { 'class': 'mac-filter-title' }, [
			E('div', { 'class': 'mac-title-row' }, [
				E('span', { 'class': 'mac-title-icon' }, icon('shield')),
				E('div', {}, [
					E('h1', {}, _('MAC Filtering')),
					E('p', {}, _('Control allowed or blocked client MAC addresses per SSID.'))
				])
			])
		]),
		E('section', { 'class': 'mac-panel' }, [
			E('div', { 'class': 'mac-panel-head' }, [ icon('list'), E('h2', {}, _('Feature not ready')) ]),
			E('div', { 'class': 'mac-policy-strip' }, message)
		])
	]);
}

return view.extend({
	load: function() {
		return callHealth().then(function(health) {
			if (!health || health.ok === false)
				return { unavailable: rpcError(health, _('AirUI backend is unavailable')) };

			return callConfig().then(function(config) {
				if (!config || config.ok === false)
					return { unavailable: rpcError(config, _('MAC filter backend is unavailable')) };

				return buildMacFilterData(config);
			});
		}).catch(function(err) {
			return { unavailable: err.message || _('MAC filter backend is unavailable') };
		});
	},

	render: function(data) {
		var policies = asArray(data && data.policies);
		var global = data && data.global ? data.global : {};
		var hashSection = window.location.hash ? decodeURIComponent(window.location.hash.slice(1)) : null;
		var selected = null;
		var modeSelect;
		var enabledToggle;
		var bulkModeSelect;

		if (data && data.unavailable)
			return renderUnavailable(data.unavailable);

		if (!selectedSection)
			selectedSection = hashSection || (policies[0] && policies[0].section);

		for (var i = 0; i < policies.length; i++) {
			if (policies[i].section == selectedSection) {
				selected = policies[i];
				break;
			}
		}
		if (!selected && policies.length) {
			selected = policies[0];
			selectedSection = selected.section;
		}

		enabledToggle = E('input', {
			'type': 'checkbox',
			'checked': selected && selected.filter_enabled ? 'checked' : null
		});
		modeSelect = E('select', {}, [
			E('option', { 'value': 'deny', 'selected': !selected || selected.mode != 'allow' ? 'selected' : null }, _('Deny list')),
			E('option', { 'value': 'allow', 'selected': selected && selected.mode == 'allow' ? 'selected' : null }, _('Allow list'))
		]);

		enabledToggle.addEventListener('change', function() {
			if (selected)
				setPolicy(selected.section, enabledToggle.checked, modeSelect.value);
		});
		modeSelect.addEventListener('change', function() {
			if (selected)
				setPolicy(selected.section, enabledToggle.checked, modeSelect.value);
		});
		bulkModeSelect = E('select', { 'class': 'mac-bulk-mode' }, [
			E('option', { 'value': 'deny' }, _('Deny list')),
			E('option', { 'value': 'allow' }, _('Allow list'))
		]);

		return E('div', { 'class': 'mac-filter-page' }, [
			E('section', { 'class': 'mac-filter-title' }, [
				E('div', { 'class': 'mac-breadcrumb' }, [
					E('span', {}, _('Security')),
					E('b', {}, '›'),
					E('strong', {}, _('MAC Filtering'))
				]),
				E('div', { 'class': 'mac-title-row' }, [
					E('span', { 'class': 'mac-title-icon' }, icon('shield')),
					E('div', {}, [
						E('h1', {}, _('MAC Filtering')),
						E('p', {}, _('Control allowed or blocked client MAC addresses per SSID.'))
					])
				])
			]),
			E('section', { 'class': 'mac-stats' }, [
				stat('filter', _('Filtering Mode'), selected ? (selected.mode_label || _('Deny list')) : _('Deny list'), _('Selected SSID'), 'is-orange'),
				stat('wifi', _('Active SSIDs'), global.active_ssids || 0, _('With MAC filtering enabled'), 'is-purple'),
				stat('users', _('Total Entries'), global.total_entries || 0, _('Across all SSID policies'), 'is-blue'),
				stat('shield', _('Status'), global.enabled ? _('Enabled') : _('Disabled'), _('MAC filtering policy'), global.enabled ? 'is-green' : '')
			]),
			E('section', { 'class': 'mac-panel mac-policy-panel' }, [
				E('div', { 'class': 'mac-panel-head' }, [ icon('list'), E('h2', {}, _('Bulk Policy Tools')) ]),
				E('div', { 'class': 'mac-policy-strip mac-policy-bulk-strip' }, [
					E('div', {}, [
						E('strong', {}, _('Target SSIDs')),
						E('span', {}, _('Use the checkboxes in SSID Policies. The current SSID is preselected.'))
					]),
					E('div', { 'class': 'mac-bulk-control' }, [
						E('div', {}, [
							E('strong', {}, _('Bulk mode')),
							E('span', {}, _('Apply allow list or deny list to selected SSIDs.'))
						]),
						bulkModeSelect
					]),
					E('div', { 'class': 'mac-bulk-actions' }, [
						E('button', { 'class': 'mac-outline-button', 'type': 'button', 'click': function() {
							setPolicies(policies, checkedPolicies(policies), true, null);
						} }, _('Enable')),
						E('button', { 'class': 'mac-outline-button', 'type': 'button', 'click': function() {
							setPolicies(policies, checkedPolicies(policies), false, null);
						} }, _('Disable')),
						E('button', { 'class': 'mac-outline-button', 'type': 'button', 'click': function() {
							setPolicies(policies, checkedPolicies(policies), null, bulkModeSelect.value);
						} }, _('Apply mode'))
					]),
					E('div', { 'class': 'mac-policy-note' }, [
						E('span', {}, 'i'),
						E('p', {}, _('Use bulk add when the same client should be allowed or blocked on multiple SSIDs.'))
					])
				])
			]),
			E('section', { 'class': 'mac-panel' }, [
				E('div', { 'class': 'mac-panel-head mac-panel-actions' }, [
					E('div', {}, [
						E('div', { 'class': 'mac-panel-title' }, [ icon('wifi'), E('h2', {}, _('SSID Policies')) ]),
						E('p', {}, _('Select SSIDs, change per-SSID mode inline, or open one SSID to inspect entries.'))
					]),
					E('button', {
						'class': 'mac-primary-button',
						'type': 'button',
						'click': function() {
							addEntry(policies, checkedPolicies(policies));
						}
					}, [ icon('plus'), _('Add MAC to SSIDs') ])
				]),
				E('div', { 'class': 'mac-policy-table' }, policyRows(policies, selected))
			]),
			E('section', { 'class': 'mac-panel' }, [
				E('div', { 'class': 'mac-panel-head mac-panel-actions' }, [
					E('div', {}, [
						E('div', { 'class': 'mac-panel-title' }, [
							icon('list'),
							E('h2', {}, _('Entries — %s').format(selected ? selected.ssid : '-'))
						]),
						E('p', {}, _('Showing MAC addresses and status for this SSID only.'))
					]),
					E('div', { 'class': 'mac-entry-tools' }, [
						E('label', { 'class': 'mac-search' }, [
							icon('search'),
							E('input', { 'type': 'search', 'placeholder': _('Search MAC or label...') })
						]),
						E('button', {
							'class': 'mac-primary-button',
							'type': 'button',
							'disabled': selected ? null : 'disabled',
							'click': function() {
								if (selected)
									addEntry(policies, [ selected.section ]);
							}
						}, [ icon('plus'), _('Add MAC') ])
					])
				]),
				E('div', { 'class': 'mac-entry-table' }, entryRows(selected))
			]),
			E('div', { 'class': 'mac-actions-bar' }, [
				E('button', { 'class': 'mac-footer-button', 'type': 'button', 'click': function() { window.location.reload(); } }, _('Cancel')),
				E('button', { 'class': 'mac-footer-button is-save', 'type': 'button', 'click': function() {
					if (selected)
						setPolicy(selected.section, enabledToggle.checked, modeSelect.value);
				} }, _('Save')),
				E('button', { 'class': 'mac-footer-button is-apply', 'type': 'button', 'click': function() {
					if (selected)
						setPolicy(selected.section, enabledToggle.checked, modeSelect.value);
				} }, _('Save & Apply'))
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
