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

/* Network / Quick setup: the proxy test. This browser is the outside client: it sends the forged
   headers to the site's own address and hands the plugin's answer back to the server to judge. */
(function () {
    'use strict';

    var btn = document.querySelector('[data-cps-probe]');

    if (!btn || !window.fetch) {
        return;
    }

    btn.addEventListener('click', function () {
        var status = document.getElementById(btn.getAttribute('data-status'));
        var form = document.getElementById(btn.getAttribute('data-form'));
        var headers;

        try {
            headers = JSON.parse(btn.getAttribute('data-headers'));
        } catch (e) {
            return;
        }

        btn.disabled = true;
        status.textContent = btn.getAttribute('data-busy');

        // Always this page's own origin (the site may be reached as www or not, http or https):
        // only the folder of the site comes from the server.
        var target = window.location.origin + new URL(btn.getAttribute('data-url'), window.location.href).pathname;

        fetch(target, {
            method: 'GET',
            headers: headers,
            credentials: 'omit',
            cache: 'no-store',
            redirect: 'error'
        }).then(function (r) {
            if (!r.ok) {
                throw new Error('status');
            }

            return r.text();
        }).then(function (text) {
            form.querySelector('[name=report]').value = text;
            form.submit();
        }).catch(function () {
            btn.disabled = false;
            status.textContent = btn.getAttribute('data-fail');
        });
    });
}());

/* Settings: check the access key while it is typed, and offer a generated one. */
(function () {
    'use strict';

    var helper = document.getElementById('cps-gate-helper');
    var input = document.querySelector('input[name="jform[params][gate_key]"]');

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
    var KEY = 'cps-settings-tab';

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
    var start = jumpTab || list.querySelector('.has-error');

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

            window.setTimeout(function () { jumpWrap.classList.remove('cps-jump-hl'); }, 2600);
        });
    }
}());

/* File scan: run the scan in short steps (a shared host gives every request only a few seconds). */
(function () {
    'use strict';

    var btn = document.querySelector('[data-cps-scan]');

    if (!btn || !window.fetch) {
        return;
    }

    var status = document.getElementById('cps-scan-status');
    var bar = document.getElementById('cps-scan-bar');

    function post(url) {
        var body = new FormData();

        body.append(btn.getAttribute('data-token'), '1');

        return fetch(url, { method: 'POST', body: body, credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
            if (!r.ok) {
                throw new Error('http');
            }

            return r.json();
        });
    }

    function fail() {
        btn.disabled = false;
        bar.hidden = true;
        status.textContent = btn.getAttribute('data-msg-fail');
    }

    function loop(failures) {
        post(btn.getAttribute('data-step')).then(function (j) {
            if (!j.ok) {
                throw new Error('step');
            }

            if (j.busy) {
                setTimeout(function () { loop(failures); }, 1500);

                return;
            }

            if (j.done) {
                status.textContent = btn.getAttribute('data-msg-done');
                window.location.reload();

                return;
            }

            status.textContent = btn.getAttribute('data-msg-files').replace('%d', j.seen);
            loop(0);
        }).catch(function () {
            // A step that timed out on a slow host is simply tried again a few times: the state is kept.
            if (failures < 3) {
                setTimeout(function () { loop(failures + 1); }, 1500);
            } else {
                fail();
            }
        });
    }

    btn.addEventListener('click', function () {
        btn.disabled = true;
        bar.hidden = false;
        status.textContent = btn.getAttribute('data-msg-run');

        if (btn.getAttribute('data-resume') === '1') {
            loop(0);

            return;
        }

        post(btn.getAttribute('data-start')).then(function (j) {
            if (!j.ok) {
                throw new Error('start');
            }

            loop(0);
        }).catch(fail);
    });
}());

/* File scan: look at a file's code, edit it, delete it (a copy is always kept), restore copies. */
(function () {
    'use strict';

    var dlg = document.getElementById('cps-code');

    if (!dlg || typeof dlg.showModal !== 'function' || !window.fetch) {
        return;
    }

    var cfg = {
        token: dlg.getAttribute('data-token'),
        rules: JSON.parse(dlg.getAttribute('data-rules') || '{}'),
        errs: JSON.parse(dlg.getAttribute('data-errs') || '{}'),
        str: JSON.parse(dlg.getAttribute('data-str') || '{}')
    };
    var $ = function (id) { return document.getElementById(id); };
    var ta = $('cps-code-text'), nums = $('cps-code-nums'), msg = $('cps-code-msg'), marksBox = $('cps-code-marks');
    var syntaxBox = $('cps-code-syntax'), saveBtn = $('cps-code-save'), delBtn = $('cps-code-del'), delBox = $('cps-code-delbox');
    var delGo = $('cps-code-del-go'), delInput = $('cps-code-confirm'), forceWrap = $('cps-code-force-wrap'), force = $('cps-code-force');
    var st = { path: '', hash: '', name: '', marked: {}, original: '', waitDone: false };
    var timer = null;

    function post(name, fields) {
        var body = new FormData();

        body.append(cfg.token, '1');
        Object.keys(fields || {}).forEach(function (k) {
            var v = fields[k];

            if (Array.isArray(v)) {
                v.forEach(function (x) { body.append(k + '[]', x); });
            } else {
                body.append(k, v);
            }
        });

        return fetch(dlg.getAttribute('data-url-' + name), { method: 'POST', body: body, credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
            return r.json();
        });
    }

    function say(text, bad) {
        msg.textContent = text || '';
        msg.style.color = bad ? 'var(--red-deep)' : '';
    }

    function err(j) {
        return cfg.errs[j && j.err] || cfg.str.network;
    }

    function numbers() {
        var count = ta.value.split('\n').length;
        var frag = document.createDocumentFragment();

        for (var i = 1; i <= count; i++) {
            if (st.marked[i]) {
                var sp = document.createElement('span');

                sp.className = 'cps-mk';
                sp.textContent = i;
                frag.appendChild(sp);
            } else {
                frag.appendChild(document.createTextNode(i));
            }

            if (i < count) {
                frag.appendChild(document.createTextNode('\n'));
            }
        }

        nums.textContent = '';
        nums.appendChild(frag);
        nums.scrollTop = ta.scrollTop;
    }

    function jump(line) {
        var lines = ta.value.split('\n'), pos = 0;

        for (var i = 0; i < line - 1 && i < lines.length; i++) {
            pos += lines[i].length + 1;
        }

        ta.focus();
        ta.setSelectionRange(pos, pos + (lines[line - 1] || '').length);
        ta.scrollTop = Math.max(0, (line - 4) * 24);
        nums.scrollTop = ta.scrollTop;
    }

    function showMarks(marks) {
        marksBox.textContent = '';
        st.marked = {};

        marks.forEach(function (m) {
            st.marked[m.line] = true;

            var b = document.createElement('button');

            b.type = 'button';
            b.className = 'cps-btn cps-btn-sm';
            b.textContent = cfg.str.line.replace('%d', m.line) + ' · ' + (cfg.rules[m.rule] || m.rule);
            b.addEventListener('click', function () { jump(m.line); });
            marksBox.appendChild(b);
        });

        if (!marks.length) {
            marksBox.textContent = cfg.str.no_marks;
        }
    }

    function showSyntax(syn) {
        if (syn) {
            syntaxBox.hidden = false;
            syntaxBox.textContent = cfg.str.syntax.replace('%d', syn.line) + ' ' + syn.message;
        } else {
            syntaxBox.hidden = true;
        }
    }

    function open(path) {
        st.path = path;
        $('cps-code-title').textContent = path;
        $('cps-code-meta').textContent = '';
        ta.value = '';
        ta.readOnly = true;
        saveBtn.disabled = true;
        delBtn.disabled = true;
        delBox.hidden = true;
        forceWrap.hidden = true;
        force.checked = false;
        syntaxBox.hidden = true;
        marksBox.textContent = '';
        numbers();
        say(cfg.str.loading);

        if (!dlg.open) {
            dlg.showModal();
        }

        post('view', { path: path }).then(function (j) {
            if (!j.ok) {
                say(err(j), true);

                return;
            }

            st.hash = j.hash;
            st.name = j.name;
            st.original = j.content;
            ta.value = j.content;
            ta.readOnly = !j.canEdit;
            saveBtn.disabled = !j.canEdit;
            delBtn.disabled = !j.canDelete;
            delBtn.title = j.canDelete ? '' : (cfg.errs[j.deleteWhy] || '');
            $('cps-code-meta').textContent = j.size + ' B' + (j.binary ? ' · ' + cfg.str.binary : (j.canEdit ? '' : ' · ' + cfg.str.readonly));
            showMarks(j.marks || []);
            showSyntax(j.syntax);
            numbers();
            say('');

            if (j.marks && j.marks.length) {
                jump(j.marks[0].line);
            }
        }).catch(function () { say(cfg.str.network, true); });
    }

    function close() {
        if (ta.value !== st.original && !ta.readOnly && !window.confirm(cfg.str.drop_confirm)) {
            return;
        }

        window.clearTimeout(timer);
        dlg.close();
    }

    ta.addEventListener('input', function () { numbers(); });
    ta.addEventListener('scroll', function () { nums.scrollTop = ta.scrollTop; });
    $('cps-code-close').addEventListener('click', close);
    dlg.addEventListener('cancel', function (ev) {
        if (ta.value !== st.original && !ta.readOnly && !window.confirm(cfg.str.drop_confirm)) {
            ev.preventDefault();
        }
    });

    saveBtn.addEventListener('click', function () {
        saveBtn.disabled = true;
        say(cfg.str.saving);
        post('save', { path: st.path, content: ta.value, base: st.hash, force: force.checked ? '1' : '0' }).then(function (j) {
            saveBtn.disabled = false;

            if (j.ok) {
                st.hash = j.hash;
                st.original = ta.value;
                showMarks(j.marks || []);
                showSyntax(j.syntax);
                forceWrap.hidden = true;
                force.checked = false;
                numbers();
                say(cfg.str.saved);

                return;
            }

            if (j.err === 'syntax' && j.syntax) {
                showSyntax(j.syntax);
                forceWrap.hidden = false;
            }

            say(err(j), true);
        }).catch(function () { saveBtn.disabled = false; say(cfg.str.network, true); });
    });

    delBtn.addEventListener('click', function () {
        delBox.hidden = false;
        delInput.value = '';
        delGo.disabled = true;
        st.waitDone = false;
        window.clearTimeout(timer);
        timer = window.setTimeout(function () { st.waitDone = true; check(); }, 3000);
        delInput.focus();
    });

    function check() {
        delGo.disabled = !(st.waitDone && delInput.value === st.name);
    }

    delInput.addEventListener('input', check);
    delGo.addEventListener('click', function () {
        delGo.disabled = true;
        post('delete', { path: st.path, confirm: delInput.value }).then(function (j) {
            if (j.ok) {
                window.location.reload();

                return;
            }

            say(err(j), true);
        }).catch(function () { say(cfg.str.network, true); });
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-cps-code]'), function (b) {
        b.addEventListener('click', function () { open(b.getAttribute('data-cps-code')); });
    });

    // Several files at once.
    var bulk = $('cps-bulk');
    var bulkSafe = $('cps-bulk-safe');
    var pickAll = $('cps-pick-all');
    var picks = function () { return Array.prototype.slice.call(document.querySelectorAll('.cps-pick:checked')); };

    if (bulk || bulkSafe) {
        Array.prototype.forEach.call(document.querySelectorAll('.cps-pick'), function (c) {
            c.addEventListener('change', function () {
                var n = picks().length;

                if (bulk) { bulk.disabled = n === 0; }

                if (bulkSafe) { bulkSafe.disabled = n === 0; }
            });
        });
    }

    if (pickAll) {
        pickAll.addEventListener('change', function () {
            Array.prototype.forEach.call(document.querySelectorAll('.cps-pick'), function (c) {
                c.checked = pickAll.checked;
                c.dispatchEvent(new Event('change'));
            });
        });
    }

    if (bulk) {
        bulk.addEventListener('click', function () {
            var list = picks().map(function (c) { return c.value; });

            if (!list.length || !window.confirm(bulk.getAttribute('data-confirm').replace('%d', list.length))) {
                return;
            }

            bulk.disabled = true;
            post('bulk', { paths: list }).then(function (j) {
                if (j.errors && j.errors.length) {
                    window.alert(j.errors.slice(0, 10).map(function (e) { return e.path + ': ' + (cfg.errs[e.err] || e.err); }).join('\n'));
                }

                window.location.reload();
            }).catch(function () { window.alert(cfg.str.network); bulk.disabled = false; });
        });
    }

    if (bulkSafe) {
        bulkSafe.addEventListener('click', function () {
            var list = picks().map(function (c) { return c.value; });

            if (!list.length) {
                return;
            }

            bulkSafe.disabled = true;
            post('bulksafe', { paths: list }).then(function (j) {
                if (j.errors && j.errors.length) {
                    window.alert(j.errors.slice(0, 10).map(function (e) { return e.path + ': ' + (cfg.errs[e.err] || e.err); }).join('\n'));
                }

                window.location.reload();
            }).catch(function () { window.alert(cfg.str.network); bulkSafe.disabled = false; });
        });
    }

    // Act on every finding matching the current severity/path filter, not only the rows picked.
    var filterBulkBox = $('cps-scan-filterbulk');

    if (filterBulkBox && window.fetch) {
        Array.prototype.forEach.call(filterBulkBox.querySelectorAll('[data-cps-filterbulk]'), function (btn) {
            btn.addEventListener('click', function () {
                var confirmMsg = btn.getAttribute('data-confirm');

                if (confirmMsg && !window.confirm(confirmMsg)) {
                    return;
                }

                var body = new FormData();

                body.append(filterBulkBox.getAttribute('data-token'), '1');
                body.append('action', btn.getAttribute('data-cps-filterbulk'));
                body.append('sev', filterBulkBox.getAttribute('data-sev') || '');
                body.append('q', filterBulkBox.getAttribute('data-q') || '');

                Array.prototype.forEach.call(filterBulkBox.querySelectorAll('[data-cps-filterbulk]'), function (b) { b.disabled = true; });

                fetch(filterBulkBox.getAttribute('data-url'), { method: 'POST', body: body, credentials: 'same-origin', cache: 'no-store' })
                    .then(function (r) { return r.json(); })
                    .then(function () { window.location.reload(); })
                    .catch(function () {
                        window.alert(cfg.str.network);
                        Array.prototype.forEach.call(filterBulkBox.querySelectorAll('[data-cps-filterbulk]'), function (b) { b.disabled = false; });
                    });
            });
        });
    }

    // Copies: put back, or remove for good.
    Array.prototype.forEach.call(document.querySelectorAll('[data-cps-restore]'), function (b) {
        b.addEventListener('click', function () {
            var id = b.getAttribute('data-cps-restore');

            post('restore', { id: id, overwrite: '0' }).then(function (j) {
                if (j.ok) {
                    window.alert(cfg.str.restored);
                    window.location.reload();

                    return;
                }

                if (j.err === 'exists' && window.confirm(cfg.str.restore_overwrite)) {
                    return post('restore', { id: id, overwrite: '1' }).then(function (k) {
                        if (k.ok) {
                            window.location.reload();
                        } else {
                            window.alert(err(k));
                        }
                    });
                }

                if (j.err !== 'exists') {
                    window.alert(err(j));
                }
            });
        });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-cps-drop]'), function (b) {
        b.addEventListener('click', function () {
            if (window.confirm(cfg.str.copy_drop_confirm)) {
                post('drop', { id: b.getAttribute('data-cps-drop') }).then(function () { window.location.reload(); });
            }
        });
    });
}());
