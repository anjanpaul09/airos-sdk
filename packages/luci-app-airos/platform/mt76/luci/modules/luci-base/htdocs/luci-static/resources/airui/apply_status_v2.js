'use strict';
'require baseclass';
'require rpc';

var callApplyStatus = rpc.declare({
	object: 'airui.system',
	method: 'apply_status',
	expect: { '': {} }
});
var running = {};

function normalizeState(state) {
	state = String(state || 'idle').toLowerCase().replace(/[_ ]+/g, '-');

	if (state == 'pending' || state == 'running' || state == 'in-progress')
		return 'applying';
	if (state == 'ok' || state == 'complete' || state == 'completed' || state == 'applied')
		return 'success';
	if (state == 'error' || state == 'failed')
		return 'failure';
	if (state == 'rolling-back' || state == 'rolled-back' || state == 'rollback-complete')
		return 'rollback';

	return state;
}

function banner() {
	var root = document.querySelector('.air-page, .air-settings-page, .wireless-page, .interface-page, .mac-filter-page, .airdash');
	var node = document.querySelector('.airui-apply-status');

	if (!node && root) {
		node = E('div', { 'class': 'airui-apply-status', 'role': 'status', 'aria-live': 'polite' });
		root.insertBefore(node, root.firstChild);
	}

	return node;
}

function show(state, message) {
	var node = banner();
	if (!node)
		return;

	state = normalizeState(state);
	node.className = 'airui-apply-status is-' + state;
	node.textContent = message;
	node.hidden = state == 'idle' && !message;
	node.setAttribute('aria-busy', state == 'loading' || state == 'applying' ? 'true' : 'false');
	node.setAttribute('role', state == 'failure' || state == 'rollback' || state == 'stale' ? 'alert' : 'status');
}

function setControlsBusy(busy, root) {
	root = root || document;
	var selector = [
		'.air-action', '.wireless-save', '.mac-primary-button',
		'.cbi-button-save', '.cbi-button-apply', '.cbi-button-positive',
		'button.is-primary', 'button.primary'
	].join(',');

	root.querySelectorAll(selector).forEach(function(button) {
		if (busy) {
			if (!button.hasAttribute('data-airui-was-disabled'))
				button.setAttribute('data-airui-was-disabled', button.disabled ? '1' : '0');
			button.disabled = true;
			button.setAttribute('aria-busy', 'true');
		}
		else if (button.hasAttribute('data-airui-was-disabled')) {
			button.disabled = button.getAttribute('data-airui-was-disabled') == '1';
			button.removeAttribute('data-airui-was-disabled');
			button.removeAttribute('aria-busy');
		}
	});
}

function refresh() {
	return callApplyStatus().then(function(response) {
		if (!response || response.ok === false || !response.data)
			throw new Error('Invalid apply-status response');

		var status = response.data;
		status.state = normalizeState(status.state);
		show(status.state, status.message || _('Configuration status unavailable'));
		return status;
	});
}

function terminalStatus(operation, attempts) {
	attempts = attempts == null ? 20 : attempts;

	return refresh().then(function(status) {
		if (status.state == 'failure')
			throw new Error(status.message || _('%s failed.').format(operation));
		if (status.state == 'rollback') {
			show('rollback', status.message || _('%s was rolled back.').format(operation));
			return status;
		}
		if (status.state == 'applying' && status.terminal !== true && attempts > 0)
			return new Promise(function(resolve) {
				window.setTimeout(resolve, 750);
			}).then(function() {
				return terminalStatus(operation, attempts - 1);
			});
		if (status.state == 'applying') {
			show('applying', status.message || _('Applying %s...').format(operation));
			return status;
		}

		show('success', status.state == 'idle' ?
			_('%s applied successfully.').format(operation) :
			(status.message || _('%s applied successfully.').format(operation)));
		return status;
	}).catch(function(error) {
		var message = error && error.message ? error.message :
			_('Apply status is unavailable. Refresh the page to confirm whether the change succeeded.');

		show('failure', message);
		throw error || new Error(message);
	});
}

function run(key, operation, task, root) {
	key = key || 'configuration';
	operation = operation || _('Configuration');

	if (running[key])
		return running[key];

	show('applying', _('Applying %s...').format(operation));
	setControlsBusy(true, root);

	var request = Promise.resolve().then(task).then(function(result) {
		return terminalStatus(operation).then(function() { return result; });
	}).catch(function(error) {
		show('failure', error && error.message ? error.message : _('%s failed.').format(operation));
		throw error;
	});

	running[key] = request.then(function(result) {
		delete running[key];
		setControlsBusy(false, root);
		return result;
	}, function(error) {
		delete running[key];
		setControlsBusy(false, root);
		throw error;
	});

	return running[key];
}

function track(promise, operation) {
	return run('legacy', operation, function() { return promise; });
}

function dataState(root, state, message) {
	if (!root)
		return null;

	var node = root.querySelector('.airui-data-state');
	if (!node) {
		node = E('div', { 'class': 'airui-data-state', 'role': 'status', 'aria-live': 'polite' });
		root.insertBefore(node, root.firstChild);
	}

	state = normalizeState(state);
	node.className = 'airui-data-state is-' + state;
	node.textContent = message || '';
	node.hidden = !message;
	node.setAttribute('role', state == 'failure' || state == 'stale' ? 'alert' : 'status');
	node.setAttribute('aria-busy', state == 'loading' ? 'true' : 'false');
	return node;
}

return baseclass.extend({
	refresh: refresh,
	show: show,
	track: track,
	run: run,
	dataState: dataState,
	isRunning: function(key) { return !!running[key || 'configuration']; }
});
