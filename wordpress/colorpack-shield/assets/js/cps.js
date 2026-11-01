/* Colorpack Shield admin (WordPress): vanilla JS, no framework, no build step. The Basic / Advanced switch,
   tabs, the access-key helper and "ask before deleting" come from the Joomla edition's cps.js; the
   scan screen keeps its own inline script. */
/* Colorpack Shield admin: the Basic / Advanced switch on the Settings screen. Nothing else. */
(function () {
    'use strict';

    var app = document.getElementById('cps-app');
    var toggle = document.getElementById('cps-toggle-advanced');

    if (!app || !toggle) {
        return;
    }

    var advLabel = toggle.querySelector('.cps-adv-toggle-label');

    toggle.addEventListener('click', function () {
        var on = app.classList.toggle('cps-show-adv');

        toggle.setAttribute('aria-pressed', on ? 'true' : 'false');

        if (advLabel) {
            advLabel.textContent = on ? toggle.getAttribute('data-hide') : toggle.getAttribute('data-show');
        }
    });
}());


/* A button that deletes something asks first (data-cps-confirm holds the question). */
(function () {
    'use strict';

    document.querySelectorAll('[data-cps-confirm]').forEach(function (btn) {
        btn.addEventListener('click', function (ev) {
            if (!window.confirm(btn.getAttribute('data-cps-confirm'))) {
                ev.preventDefault();
            }
        });
    });
}());


/* Server rules screen: copy a generated text to the clipboard. */
(function () {
    'use strict';

    document.querySelectorAll('[data-cps-copy]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var src = document.getElementById(btn.getAttribute('data-cps-copy'));

            if (!src) {
                return;
            }

            var done = function () {
                var old = btn.textContent;

                btn.textContent = btn.getAttribute('data-done') || old;
                setTimeout(function () { btn.textContent = old; }, 2000);
            };

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(src.textContent).then(done, function () {});

                return;
            }

            var range = document.createRange();

            range.selectNodeContents(src);

            var sel = window.getSelection();

            sel.removeAllRanges();
            sel.addRange(range);

            try {
                document.execCommand('copy');
                done();
            } catch (e) { /* the text stays selected for a manual copy */ }
        });
    });
}());


/* Settings: check the access key while it is typed, and offer a generated one. */
(function () {
    'use strict';

    var helper = document.getElementById('cps-gate-helper');
    var input = document.querySelector('input[name="gate_key"]');

    if (!helper || !input) {
        return;
    }

    var min = parseInt(helper.getAttribute('data-min'), 10);
    var max = parseInt(helper.getAttribute('data-max'), 10);
    var alphabet = helper.getAttribute('data-alphabet');
    var length = parseInt(helper.getAttribute('data-length'), 10);
    var msg = document.createElement('span');
    var btn = document.createElement('button');

    btn.type = 'button';
    btn.className = 'cps-btn cps-btn-sm';
    btn.textContent = helper.getAttribute('data-button');
    helper.appendChild(btn);
    helper.appendChild(document.createTextNode(' '));
    helper.appendChild(msg);

    function check() {
        var v = input.value.trim();
        var text = helper.getAttribute('data-ok');
        var bad = false;

        if (v === '') {
            text = helper.getAttribute('data-empty');
        } else if (!/^[A-Za-z0-9_-]+$/.test(v)) {
            text = helper.getAttribute('data-chars');
            bad = true;
        } else if (v.length < min) {
            text = helper.getAttribute('data-short').replace('%d', v.length).replace('%s', min);
            bad = true;
        } else if (v.length > max) {
            text = helper.getAttribute('data-long').replace('%s', max);
            bad = true;
        }

        msg.textContent = text + (v !== '' ? ' (' + v.length + ')' : '');
        input.setAttribute('aria-invalid', bad ? 'true' : 'false');
        input.style.borderColor = bad ? 'var(--red, #ef2b2c)' : '';
    }

    btn.addEventListener('click', function () {
        var out = '';
        var buf = new Uint32Array(length);

        window.crypto.getRandomValues(buf);

        for (var i = 0; i < length; i++) {
            out += alphabet.charAt(buf[i] % alphabet.length);
        }

        input.value = out;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.focus();
    });

    input.addEventListener('input', check);
    check();
}());


/* Settings: tabs (one group of settings at a time). The last tab is remembered per browser. */
(function () {
    'use strict';

    var app = document.getElementById('cps-app');
    var list = document.querySelector('[data-cps-tabs]');

    if (!app || !list) {
        return;
    }

    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role=tab]'));
    var KEY = list.getAttribute('data-cps-key') ? 'cps-' + list.getAttribute('data-cps-key') + '-tab' : 'cps-settings-tab';

    app.classList.add('cps-tabs-on');

    function visible(tab) {
        return tab.offsetParent !== null;
    }

    function show(tab, focus) {
        tabs.forEach(function (t) {
            var on = t === tab;
            var panel = document.getElementById(t.getAttribute('data-cps-panel'));

            t.setAttribute('aria-selected', on ? 'true' : 'false');
            t.tabIndex = on ? 0 : -1;

            if (panel) {
                panel.hidden = !on;
            }
        });

        if (focus) {
            tab.focus();
        }

        try {
            window.localStorage.setItem(KEY, tab.id);
        } catch (e) { /* remembering is a convenience only */ }
    }

    tabs.forEach(function (t) {
        t.addEventListener('click', function () { show(t, false); });
        t.addEventListener('keydown', function (ev) {
            var shown = tabs.filter(visible);
            var i = shown.indexOf(t);
            var next = null;

            if (ev.key === 'ArrowRight') { next = shown[(i + 1) % shown.length]; }
            else if (ev.key === 'ArrowLeft') { next = shown[(i - 1 + shown.length) % shown.length]; }
            else if (ev.key === 'Home') { next = shown[0]; }
            else if (ev.key === 'End') { next = shown[shown.length - 1]; }

            if (next) {
                ev.preventDefault();
                show(next, true);
            }
        });
    });

    // Switching "advanced" off while an advanced-only tab is open: go back to the first tab.
    var adv = document.getElementById('cps-toggle-advanced');

    if (adv) {
        adv.addEventListener('click', function () {
            var current = tabs.filter(function (t) { return t.getAttribute('aria-selected') === 'true'; })[0];

            if (current && !visible(current)) {
                show(tabs.filter(visible)[0], false);
            }
        });
    }

    // A Dashboard recommendation sent us straight to one field: reveal "advanced" if that field
    // needs it, open its tab, then scroll to it and flash it so the eye finds it at once.
    var jumpForm = list.closest('form');
    var jumpField = jumpForm ? jumpForm.getAttribute('data-cps-jump') : null;
    var jumpWrap = jumpField ? document.getElementById('cps-f-' + jumpField) : null;
    var jumpTab = null;

    if (jumpWrap) {
        app.classList.add('cps-show-adv');

        if (adv) {
            adv.setAttribute('aria-pressed', 'true');

            var jumpLabel = adv.querySelector('.cps-adv-toggle-label');

            if (jumpLabel) {
                jumpLabel.textContent = adv.getAttribute('data-hide');
            }
        }

        var jumpPanel = jumpWrap.closest('.cps-panel');

        if (jumpPanel) {
            jumpTab = tabs.filter(function (t) { return t.getAttribute('data-cps-panel') === jumpPanel.id; })[0] || null;
        }
    }

    // Start on: the jumped-to field's tab, else a tab with an error, else the remembered one, else the first.
    var hashName = window.location.hash ? window.location.hash.slice(1) : '';
    var hashTab = hashName && list.getAttribute('data-cps-key') ? document.getElementById('cps-tab-' + list.getAttribute('data-cps-key') + '-' + hashName) : null;
    var start = jumpTab || hashTab || list.querySelector('.has-error');

    if (!start) {
        try {
            start = document.getElementById(window.localStorage.getItem(KEY) || '');
        } catch (e) { start = null; }
    }

    if (start && !visible(start)) {
        start = null;
    }

    show(start || tabs.filter(visible)[0] || tabs[0], false);

    if (jumpWrap) {
        window.requestAnimationFrame(function () {
            jumpWrap.scrollIntoView({ behavior: 'smooth', block: 'center' });
            jumpWrap.classList.add('cps-jump-hl');

            var field = jumpWrap.querySelector('input, select, textarea');

            if (field) {
                field.focus({ preventScroll: true });
            }

            window.setTimeout(function () { jumpWrap.classList.remove('cps-jump-hl'); }, 3400);
        });
    }
}());


/* A setting that only matters when another one has a value (data-cps-showon="field:1" or "field:a,b"). */
(function () {
    'use strict';

    var nodes = document.querySelectorAll('[data-cps-showon]');

    function value(name) {
        var radios = document.querySelectorAll('[name="' + name + '"]');

        if (!radios.length) {
            return '';
        }

        if (radios[0].type === 'radio') {
            var on = Array.prototype.filter.call(radios, function (r) { return r.checked; })[0];

            return on ? on.value : '';
        }

        return radios[0].value;
    }

    function update() {
        nodes.forEach(function (n) {
            var parts = n.getAttribute('data-cps-showon').split(':');
            var show = (parts[1] || '').split(',').indexOf(value(parts[0])) !== -1;

            n.hidden = !show;
        });
    }

    document.addEventListener('change', update);
    update();
}());
