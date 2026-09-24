(function() {
	'use strict';

	var lastFocused = null;
	var activeDialog = null;
	var toastRegion = null;
	var focusable = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

	function visible(node) {
		return !!(node && (node.offsetWidth || node.offsetHeight || node.getClientRects().length));
	}

	function labelControls(root) {
		(root || document).querySelectorAll('button, input, select, textarea').forEach(function(control) {
			if (control.getAttribute('aria-label') || control.getAttribute('aria-labelledby'))
				return;
			var id = control.id;
			var explicit = id && document.querySelector('label[for="' + CSS.escape(id) + '"]');
			var wrapped = control.closest('label');
			if (explicit || wrapped)
				return;
			var label = control.getAttribute('title') || control.getAttribute('placeholder') || control.getAttribute('name');
			if (control.tagName == 'BUTTON')
				label = (control.textContent || '').trim() || label;
			if (label)
				control.setAttribute('aria-label', label);
		});
	}

	function ensureToastRegion() {
		if (toastRegion && toastRegion.isConnected)
			return toastRegion;
		toastRegion = document.getElementById('airui-toast-region');
		if (!toastRegion) {
			toastRegion = document.createElement('div');
			toastRegion.id = 'airui-toast-region';
			toastRegion.setAttribute('aria-live', 'polite');
			toastRegion.setAttribute('aria-relevant', 'additions text');
			document.body.appendChild(toastRegion);
		}
		return toastRegion;
	}

	function toastKey(notification) {
		var copy = notification.cloneNode(true);
		copy.querySelectorAll('button').forEach(function(button) { button.remove(); });
		return (copy.textContent || '').replace(/\s+/g, ' ').trim();
	}

	function moveNotifications() {
		var region = ensureToastRegion();
		document.querySelectorAll('#maincontent > .alert-message').forEach(function(notification) {
			var key = toastKey(notification);
			Array.prototype.forEach.call(region.children, function(existing) {
				if (key && existing.dataset.airuiToastKey === key)
					existing.remove();
			});
			notification.dataset.airuiToastKey = key;
			notification.setAttribute('role', notification.classList.contains('error') || notification.classList.contains('danger') ? 'alert' : 'status');
			region.appendChild(notification);
		});
	}

	function prepareDialog(dialog) {
		if (!dialog || dialog === activeDialog)
			return;
		lastFocused = document.activeElement;
		activeDialog = dialog;
		dialog.setAttribute('role', 'dialog');
		dialog.setAttribute('aria-modal', 'true');
		var heading = dialog.querySelector('h1, h2, h3, .modal-title');
		if (heading) {
			if (!heading.id)
				heading.id = 'airui-dialog-title-' + Date.now();
			dialog.setAttribute('aria-labelledby', heading.id);
		}
		labelControls(dialog);
		var first = Array.prototype.find.call(dialog.querySelectorAll(focusable), visible);
		if (first)
			window.setTimeout(function() { first.focus(); }, 0);
	}

	function scan(root) {
		labelControls(root);
		moveNotifications();
		var dialog = document.querySelector('#modal_overlay .cbi-modal, #modal_overlay [role="dialog"]');
		if (dialog)
			prepareDialog(dialog);
		else if (activeDialog) {
			activeDialog = null;
			if (visible(lastFocused))
				lastFocused.focus();
		}
	}

	document.addEventListener('keydown', function(event) {
		if (!activeDialog || event.key !== 'Tab')
			return;
		var items = Array.prototype.filter.call(activeDialog.querySelectorAll(focusable), visible);
		if (!items.length) {
			event.preventDefault();
			return;
		}
		var first = items[0];
		var last = items[items.length - 1];
		if (event.shiftKey && document.activeElement === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && document.activeElement === last) {
			event.preventDefault();
			first.focus();
		}
	});

	document.addEventListener('DOMContentLoaded', function() {
		ensureToastRegion();
		scan(document);
		new MutationObserver(function(records) {
			records.forEach(function(record) {
				record.addedNodes.forEach(function(node) {
					if (node.nodeType === 1)
						scan(node);
				});
			});
			scan(document);
		}).observe(document.body, { childList: true, subtree: true });
	});
})();
