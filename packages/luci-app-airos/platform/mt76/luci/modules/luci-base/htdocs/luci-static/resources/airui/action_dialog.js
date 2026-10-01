'use strict';
'require baseclass';
'require ui';

var running = {};

function button(label, className, handler) {
	return E('button', {
		'class': className,
		'type': 'button',
		'click': handler
	}, label);
}

function confirm(options) {
	options = options || {};

	return new Promise(function(resolve) {
		var settled = false;
		var finish = function(value) {
			if (settled)
				return;
			settled = true;
			ui.hideModal();
			resolve(value);
		};

		ui.showModal(options.title || _('Confirm action'), [
			E('div', {
				'class': 'airui-action-message',
				'role': 'alert'
			}, [
				E('strong', {}, options.heading || options.title || _('Confirm action')),
				E('p', {}, options.message || _('This action cannot be undone.'))
			]),
			E('div', { 'class': 'right airui-action-buttons' }, [
				button(_('Cancel'), 'btn', function() { finish(false); }),
				button(options.confirmLabel || _('Continue'), options.danger ? 'btn cbi-button cbi-button-negative' : 'btn cbi-button cbi-button-apply', function() { finish(true); })
			])
		], 'cbi-modal', 'airui-action-dialog');
	});
}

function progress(options) {
	options = options || {};
	ui.showModal(options.title || _('Working'), [
		E('div', {
			'class': 'airui-action-progress is-running',
			'role': 'status',
			'aria-live': 'assertive',
			'aria-busy': 'true'
		}, [
			E('span', { 'class': 'airui-action-spinner', 'aria-hidden': 'true' }),
			E('div', {}, [
				E('strong', {}, options.heading || _('Request in progress')),
				E('p', {}, options.message || _('Please wait. Do not close this page.'))
			])
		])
	], 'cbi-modal', 'airui-action-dialog', 'airui-action-dialog-locked');
}

function run(key, options, task) {
	if (running[key])
		return running[key];

	running[key] = confirm(options).then(function(approved) {
		if (!approved)
			return null;

		progress({
			title: options.progressTitle || options.title,
			heading: options.progressHeading,
			message: options.progressMessage
		});

		return Promise.resolve().then(task).then(function(result) {
			ui.hideModal();
			return result;
		}, function(error) {
			ui.hideModal();
			throw error;
		});
	}).finally(function() {
		delete running[key];
	});

	return running[key];
}

return baseclass.extend({
	confirm: confirm,
	progress: progress,
	run: run,
	isRunning: function(key) { return !!running[key]; }
});
