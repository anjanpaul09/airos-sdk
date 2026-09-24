'use strict';
'require view';

return view.extend({
	render: function() {
		return E('div', { 'class': 'air-page' }, [
			E('h2', {}, _('Attack Checks')),
			E('div', { 'class': 'air-card' }, [
				E('div', { 'class': 'air-card-head' }, [
					E('h3', {}, _('Attack Check Status')),
					E('span', { 'class': 'air-refresh' })
				]),
				E('div', { 'class': 'air-detail-list' }, [
					E('div', {}, [ E('label', {}, _('Port Scan Protection')), E('strong', { 'class': 'air-ok' }, _('Enabled')) ]),
					E('div', {}, [ E('label', {}, _('SYN Flood Protection')), E('strong', { 'class': 'air-ok' }, _('Enabled')) ]),
					E('div', {}, [ E('label', {}, _('ICMP Flood Protection')), E('strong', { 'class': 'air-ok' }, _('Enabled')) ])
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
