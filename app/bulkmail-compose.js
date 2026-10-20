(function () {
    'use strict';

    var WARN_BYTES = 12 * 1024 * 1024;
    var STOP_BYTES = 15 * 1024 * 1024;
    var saveTimer = null;
    var loadingDraft = false;
    var savedImageRange = null;
    var savedEditorRange = null;
    var saveChain = Promise.resolve(true);
    var editSerial = 0;
    var savedSerial = 0;
    var draftEdited = false;
    var submitting = false;
    var allowUnload = false;

    function rememberEditorSelection() {
        var editor = byId('editor'), sel = window.getSelection();
        if (!editor || !sel || !sel.rangeCount) return;
        var range = sel.getRangeAt(0);
        if (editor.contains(range.commonAncestorContainer)) savedEditorRange = range.cloneRange();
    }
    function restoreEditorSelection() {
        var editor = byId('editor'), sel = window.getSelection();
        if (!editor || !sel) return null;
        editor.focus();
        if (savedEditorRange && editor.contains(savedEditorRange.commonAncestorContainer)) {
            sel.removeAllRanges(); sel.addRange(savedEditorRange);
        }
        return sel;
    }
    function localDraftKey() {
        var f = byId('composeForm');
        return f ? 'grange.bulkmail.' + f.dataset.userId + '.' + f.querySelector('[name="acting_for"]').value + '.' + (f.dataset.workspace || 'legacy') : '';
    }
    function storeLocalDraft(unsaved) {
        try {
            var data = draftData(); if (!data) return;
            var d = {};
            data.forEach(function (value, key) { if (key !== 'csrf') d[key] = value; });
            d.groups = JSON.parse(d.groups || '[]'); d.contacts = JSON.parse(d.contacts || '[]');
            d.all_contacts = d.all_contacts === '1';
            sessionStorage.setItem(localDraftKey(), JSON.stringify({draft:d, unsaved:unsaved, time:Date.now()}));
        } catch (e) { /* Server-side draft storage remains the primary copy. */ }
    }

    function byId(id) {
        return document.getElementById(id);
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function fmtBytes(bytes) {
        return (bytes / 1024 / 1024).toFixed(2) + ' MB';
    }

    window.fmt = function (cmd) {
        var editor = byId('editor');
        if (!editor) return;

        restoreEditorSelection();
        document.execCommand(cmd, false, null);
        rememberEditorSelection();
        syncEditorBody();
        scheduleDraftSave();
    };


    window.applyEditorFont = function (font) {
        var editor = byId('editor');
        if (!editor || !font) return;
        var sel = restoreEditorSelection();
        if (!sel) return;
        var whole = !sel.rangeCount || sel.isCollapsed || !editor.contains(sel.getRangeAt(0).commonAncestorContainer);
        if (whole) {
            editor.style.fontFamily = font;
            editor.dataset.defaultFont = font;
            if (!editor.textContent.trim() && !editor.querySelector('img')) {
                var block = document.createElement('div'); block.style.fontFamily = font;
                block.appendChild(document.createElement('br')); editor.replaceChildren(block);
            }
            var range = document.createRange(); range.selectNodeContents(editor);
            sel.removeAllRanges(); sel.addRange(range);
        }
        try { document.execCommand('styleWithCSS', false, true); } catch (e) {}
        document.execCommand('fontName', false, font);
        rememberEditorSelection();
        syncEditorBody(); scheduleDraftSave();
    };


    function spellingRegex(word) {
        return new RegExp('\\b' + word.replace(/[.*+?^$\{\}()|[\]\\]/g, '\\$&') + '\\b', 'giu');
    }

    window.replaceSpelling = function (word, replacement) {
        var form = byId('composeForm');
        var editor = byId('editor');
        var rx = spellingRegex(word);

        if (form) {
            var subject = form.querySelector('[name="subject"]');
            if (subject) {
                subject.value = subject.value.replace(rx, replacement);
            }
        }

        if (editor) {
            var walker = document.createTreeWalker(
                editor,
                NodeFilter.SHOW_TEXT,
                null
            );
            var nodes = [];
            var node;

            while ((node = walker.nextNode())) {
                nodes.push(node);
            }

            nodes.forEach(function (textNode) {
                textNode.nodeValue = textNode.nodeValue.replace(
                    spellingRegex(word),
                    replacement
                );
            });
        }

        syncEditorBody();
        scheduleDraftSave();
        window.checkSpelling();
    };

    window.checkSpelling = function () {
        var form = byId('composeForm');
        var editor = byId('editor');
        var panel = byId('spellPanel');

        if (!form || !editor || !panel) return;

        var subject = form.querySelector('[name="subject"]');
        var csrf = form.querySelector('[name="csrf"]');
        var text =
            ((subject && subject.value) ? subject.value : '') +
            '\n' +
            (editor.innerText || editor.textContent || '');

        panel.style.display = 'block';
        panel.textContent = 'Checking UK English spelling…';

        var data = new FormData();
        data.append('csrf', csrf ? csrf.value : '');
        data.append('text', text);

        fetch('?page=spellcheck_api', {
            method: 'POST',
            body: data,
            credentials: 'same-origin'
        })
        .then(function (response) {
            return response.json().then(function (json) {
                if (!response.ok || !json.ok) {
                    throw new Error(json.error || 'Spell check failed');
                }
                return json;
            });
        })
        .then(function (result) {
            panel.innerHTML = '';

            var issues = result.issues || [];
            var heading = document.createElement('div');
            heading.style.fontWeight = '700';
            heading.style.marginBottom = '6px';
            heading.textContent = issues.length
                ? issues.length + ' possible spelling issue' +
                    (issues.length === 1 ? '' : 's') + ' — UK English'
                : 'No spelling issues found — UK English';
            panel.appendChild(heading);

            if (!issues.length) {
                return;
            }

            issues.forEach(function (issue) {
                var row = document.createElement('div');
                row.className = 'spell-item';

                var word = document.createElement('b');
                word.textContent = issue.word;
                row.appendChild(word);

                if (issue.suggestions && issue.suggestions.length) {
                    var label = document.createElement('span');
                    label.textContent = ' → ';
                    row.appendChild(label);

                    issue.suggestions.forEach(function (suggestion) {
                        var button = document.createElement('button');
                        button.type = 'button';
                        button.className = 'spell-suggestion';
                        button.textContent = suggestion;
                        button.addEventListener('click', function () {
                            replaceSpelling(issue.word, suggestion);
                        });
                        row.appendChild(button);
                    });
                } else {
                    var none = document.createElement('span');
                    none.textContent = ' — no suggestion';
                    row.appendChild(none);
                }

                var ignore = document.createElement('button');
                ignore.type = 'button';
                ignore.className = 'secondary';
                ignore.textContent = 'Ignore';
                ignore.addEventListener('click', function () {
                    row.remove();
                });
                row.appendChild(ignore);

                panel.appendChild(row);
            });
        })
        .catch(function (err) {
            panel.textContent = err.message || 'Spell check failed.';
        });
    };

    window.addLink = function () {
        var editor = byId('editor');
        if (!editor) return;

        var url = window.prompt('Link address:');

        if (url) {
            editor.focus();
            document.execCommand('createLink', false, url);
            syncEditorBody();
            scheduleDraftSave();
        }
    };

    window.addInlineImage = function () {
        var editor = byId('editor');
        var input = byId('inlineImageInput');
        if (!editor || !input) return;
        editor.focus();
        var selection = window.getSelection();
        if (selection && selection.rangeCount) {
            savedImageRange = selection.getRangeAt(0).cloneRange();
        }
        input.click();
    };

    window.syncEditorBody = function () {
        var editor = byId('editor');
        var bodyField = byId('body_html');
        var fallback = byId('body_text_fallback');

        if (!bodyField) return true;

        if (!editor || editor.style.display === 'none') {
            if (fallback) fallback.value = bodyField.value || '';
            return true;
        }

        var text = (editor.innerText || editor.textContent || '').trim();
        var html = (editor.innerHTML || '').trim();

        if (text !== '' && !/<[^>]+>/.test(html)) {
            html = '<p>' +
                escapeHtml(text).replace(/\n/g, '<br>') +
                '</p>';
        }

        if (editor.dataset.defaultFont && html) {
            var wrapper = document.createElement('div');
            wrapper.style.fontFamily = editor.dataset.defaultFont;
            wrapper.innerHTML = html;
            html = wrapper.outerHTML;
        }
        bodyField.value = html;

        if (fallback) {
            fallback.value = text;
        }

        return true;
    };

    function draftStatus(message, problem) {
        var node = byId('draftStatus');

        if (!node) {
            node = document.createElement('div');
            node.id = 'draftStatus';
            node.style.marginTop = '10px';
            node.style.fontSize = '.9rem';

            var editor = byId('editor');

            if (editor && editor.parentNode) {
                editor.parentNode.appendChild(node);
            }
        }

        node.textContent = message;
        node.style.color = problem ? '#b33030' : '#66717f';
    }

    function selectedValues(name) {
        return Array.prototype.slice.call(
            document.querySelectorAll(
                'input[name="' + name + '"]:checked'
            )
        ).map(function (node) {
            return parseInt(node.value, 10);
        }).filter(function (value) {
            return !isNaN(value);
        });
    }

    function draftData() {
        var form = byId('composeForm');

        if (!form) return null;

        syncEditorBody();

        var acting = form.querySelector('[name="acting_for"]');
        var sender = form.querySelector('[name="sender_identity_id"]');
        var custom = form.querySelector('[name="custom_from"]');
        var subject = form.querySelector('[name="subject"]');
        var all = form.querySelector('[name="all_contacts"]');

        var data = new FormData();

        data.append('csrf',
            (form.querySelector('[name="csrf"]') || {}).value || ''
        );

        data.append('acting_for', acting ? acting.value : '');
        data.append('workspace_token', (form.querySelector('[name="workspace_token"]') || {}).value || '');
        data.append('sender_identity_id', sender ? sender.value : '');
        data.append('custom_from', custom ? custom.value : '');
        data.append('subject', subject ? subject.value : '');
        data.append('body_html', byId('body_html').value || '');
        data.append('all_contacts', all && all.checked ? '1' : '0');
        data.append('groups', JSON.stringify(selectedValues('groups[]')));
        data.append('contacts', JSON.stringify(selectedValues('contacts[]')));

        return data;
    }

    function saveDraft() {
        if (loadingDraft) return Promise.resolve(false);
        var form = byId('composeForm');
        if (!form) return Promise.resolve(false);
        var acting = form.querySelector('[name="acting_for"]');
        var data = draftData(), serial = editSerial;
        storeLocalDraft(true);
        saveChain = saveChain.catch(function () { return false; }).then(function () {
            draftStatus('Saving draft…', false);
            return fetch('?page=draft_api&acting_for=' + encodeURIComponent(acting ? acting.value : ''), {
                method:'POST', body:data, credentials:'same-origin', cache:'no-store'
            }).then(function (response) {
                if (!response.ok || response.redirected) throw new Error('Draft save failed');
                return response.json();
            }).then(function (result) {
                if (!result.ok) throw new Error('Draft save failed');
                if (serial === editSerial) {
                    savedSerial = serial; storeLocalDraft(false);
                    draftStatus('Draft saved automatically at ' + new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}), false);
                }
                return true;
            }).catch(function () {
                draftStatus('Not saved to the server. A recovery copy is kept in this browser tab. Keep the tab open and check your connection or sign in again.', true);
                return false;
            });
        });
        return saveChain;
    }
    function scheduleDraftSave() {
        if (submitting) return;
        draftEdited = true; editSerial++;
        storeLocalDraft(true);
        window.clearTimeout(saveTimer);
        if (!loadingDraft) saveTimer = window.setTimeout(saveDraft, 650);
    }

    function restoreChecked(name, values) {
        if (!Array.isArray(values)) return;

        var wanted = {};

        values.forEach(function (value) {
            wanted[String(value)] = true;
        });

        document.querySelectorAll(
            'input[name="' + name + '"]'
        ).forEach(function (node) {
            node.checked = !!wanted[String(node.value)];
        });
    }

    function loadDraft() {
        var form = byId('composeForm');

        if (!form) return;

        var acting = form.querySelector('[name="acting_for"]');

        loadingDraft = true;

        fetch(
            '?page=draft_api&acting_for=' +
                encodeURIComponent(acting ? acting.value : ''),
            {
                credentials: 'same-origin'
            }
        )
        .then(function (response) {
            if (!response.ok) throw new Error('Draft load failed');
            return response.json();
        })
        .then(function (result) {
            // A late response must never replace text already entered on this page.
            if (draftEdited) return;
            var d = result.draft;
            try {
                var local = JSON.parse(sessionStorage.getItem(localDraftKey()) || 'null');
                if (local && local.unsaved && local.draft && window.confirm('This browser tab has a message that did not finish saving. Restore that text?')) {
                    d = local.draft; draftEdited = true; editSerial++;
                }
            } catch (e) {}
            if (!d) return;

            var subject = form.querySelector('[name="subject"]');
            var sender = form.querySelector('[name="sender_identity_id"]');
            var custom = form.querySelector('[name="custom_from"]');
            var all = form.querySelector('[name="all_contacts"]');
            var bodyField = byId('body_html');
            var editor = byId('editor');

            if (subject) subject.value = d.subject || '';

            if (sender && d.sender_identity_id) {
                sender.value = String(d.sender_identity_id);
            }

            if (custom) custom.value = d.custom_from || '';

            if (all) all.checked = !!d.all_contacts;

            restoreChecked('groups[]', d.groups);
            restoreChecked('contacts[]', d.contacts);

            if (bodyField) bodyField.value = d.body_html || '';

            if (editor) {
                savedEditorRange = null; delete editor.dataset.defaultFont; editor.style.fontFamily = '';
                editor.innerHTML = d.body_html || '';
            }

            draftStatus(
                'Restored saved draft' +
                (d.updated_at ? ' from ' + d.updated_at + ' UTC' : '') +
                '.',
                false
            );
        })
        .catch(function () {
            draftStatus('Could not restore saved draft.', true);
        })
        .finally(function () {
            loadingDraft = false;
            if (draftEdited) saveDraft();
        });
    }

    function sharedAttachmentInputs() {
        return Array.prototype.slice.call(
            document.querySelectorAll('input[name="attachments[]"]')
        );
    }

    function attachmentTotal() {
        var total = 0;

        sharedAttachmentInputs().forEach(function (input) {
            Array.prototype.forEach.call(input.files || [], function (file) {
                total += file.size || 0;
            });
        });

        document.querySelectorAll('.retained-file[data-kind="shared"]').forEach(function (row) {var cb=row.querySelector('input');if(!cb || !cb.checked)total+=Number(row.dataset.size)||0;});
        return total;
    }

    function attachmentCount() {
        var count = 0;

        sharedAttachmentInputs().forEach(function (input) {
            count += input.files ? input.files.length : 0;
        });

        document.querySelectorAll('.retained-file[data-kind="shared"]').forEach(function (row) {var cb=row.querySelector('input');if(!cb || !cb.checked)count++;});
        return count;
    }

    function attachmentStatus() {
        var inputs = sharedAttachmentInputs();

        if (!inputs.length) return true;

        var status = byId('attachmentStatus');

        if (!status) {
            status = document.createElement('div');
            status.id = 'attachmentStatus';
            status.style.marginTop = '8px';
            status.style.padding = '10px';
            status.style.borderRadius = '7px';

            var last = inputs[inputs.length - 1];
            last.parentNode.parentNode.insertBefore(
                status,
                last.parentNode.nextSibling
            );
        }

        var total = attachmentTotal();
        var count = attachmentCount();

        if (!count) {
            status.textContent =
                'No shared attachments selected. Combined maximum: 15 MB.';
            status.style.background = '#edf0f4';
            status.style.color = '#444';
            return true;
        }

        if (total >= STOP_BYTES) {
            status.innerHTML =
                '<b>STOP:</b> ' + count +
                ' shared attachment(s), ' + fmtBytes(total) +
                ' combined. Maximum allowed is 15 MB. ' +
                'Remove one or more files before continuing.';

            status.style.background = '#fdeaea';
            status.style.color = '#8f2020';
            return false;
        }

        if (total >= WARN_BYTES) {
            status.innerHTML =
                '<b>Warning:</b> ' + count +
                ' shared attachment(s), ' + fmtBytes(total) +
                ' combined. You are approaching the 15 MB hard limit.';

            status.style.background = '#fff3ca';
            status.style.color = '#705600';
            return true;
        }

        status.innerHTML =
            '<b>' + count + '</b> shared attachment(s), ' +
            '<b>' + fmtBytes(total) + '</b> combined.';

        status.style.background = '#e8f7ec';
        status.style.color = '#245b31';

        return true;
    }

    document.addEventListener('DOMContentLoaded', function () {
        var form = byId('composeForm');
        var editor = byId('editor');
        var bodyField = byId('body_html');
        var fallback = byId('body_text_fallback');

        var senderTop = byId('customFromTop');
        var senderBottom = byId('customFromBottom');
        var contextSelect = byId('customContext');

        if (senderTop && senderBottom) {
            senderTop.addEventListener('input', function () {
                senderBottom.value = senderTop.value;
                scheduleDraftSave();
            });
        }

        if (contextSelect) {
            contextSelect.addEventListener('change', function () {
                window.location =
                    '?page=compose&acting_for=' +
                    encodeURIComponent(contextSelect.value);
            });
        }

        if (!form || !editor || !bodyField) return;

        var inlineImageInput = byId('inlineImageInput');
        var loadTemplateButton = byId('loadTemplateButton');
        var saveTemplateButton = byId('saveTemplateButton');
        var templateSelect = byId('templateSelect');

        if (inlineImageInput) {
            inlineImageInput.addEventListener('change', function () {
                var file = inlineImageInput.files && inlineImageInput.files[0];
                if (!file) return;
                var name = (file.name || '').toLowerCase();
                if (!/\.(jpe?g|png|heic|heif)$/.test(name)) {
                    window.alert('Only JPEG, PNG and HEIC images can be embedded. RAW images are not supported.');
                    inlineImageInput.value = '';
                    return;
                }
                var data = new FormData();
                data.append('csrf', (form.querySelector('[name="csrf"]') || {}).value || '');
                data.append('acting_for', (form.querySelector('[name="acting_for"]') || {}).value || '');
                data.append('editor_image', file);
                draftStatus('Uploading image…', false);
                fetch('?page=inline_image_api', {method:'POST', body:data, credentials:'same-origin'})
                    .then(function (response) { return response.json().then(function (j) { if (!response.ok || !j.ok) throw new Error(j.error || 'Image upload failed'); return j; }); })
                    .then(function (result) {
                        editor.focus();
                        if (savedImageRange) {
                            var selection = window.getSelection();
                            selection.removeAllRanges();
                            selection.addRange(savedImageRange);
                        }
                        var safeUrl = String(result.url || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
                        document.execCommand(
                            'insertHTML',
                            false,
                            '<img src="' + safeUrl + '" alt="" style="max-width:100%;height:auto">'
                        );
                        syncEditorBody();
                        scheduleDraftSave();
                        draftStatus('Image embedded and draft saved automatically.', false);
                    })
                    .catch(function (err) { window.alert(err.message || 'Image upload failed'); draftStatus('Image upload failed.', true); })
                    .finally(function () { inlineImageInput.value = ''; savedImageRange = null; });
            });
        }

        if (loadTemplateButton && templateSelect) {
            loadTemplateButton.addEventListener('click', function () {
                if (!templateSelect.value) { window.alert('Choose a template first.'); return; }
                fetch('?page=template_api&id=' + encodeURIComponent(templateSelect.value), {credentials:'same-origin'})
                    .then(function (response) { if (!response.ok) throw new Error('Template load failed'); return response.json(); })
                    .then(function (result) {
                        var t = result.template || {};
                        var subject = form.querySelector('[name="subject"]');
                        var sender = form.querySelector('[name="sender_identity_id"]');
                        if (subject) subject.value = t.subject || '';
                        if (sender && t.sender_identity_id) sender.value = String(t.sender_identity_id);
                        savedEditorRange = null; delete editor.dataset.defaultFont; editor.style.fontFamily = '';
                        editor.innerHTML = t.body_html || '';
                        syncEditorBody();
                        scheduleDraftSave();
                        draftStatus('Template loaded.', false);
                    })
                    .catch(function () { window.alert('Could not load the template.'); });
            });
        }

        if (saveTemplateButton) {
            saveTemplateButton.addEventListener('click', function () {
                syncEditorBody();
                var name = window.prompt('Template name:');
                if (!name) return;
                var data = new FormData();
                data.append('csrf', (form.querySelector('[name="csrf"]') || {}).value || '');
                data.append('acting_for', (form.querySelector('[name="acting_for"]') || {}).value || '');
                data.append('sender_identity_id', (form.querySelector('[name="sender_identity_id"]') || {}).value || '');
                data.append('name', name);
                data.append('subject', (form.querySelector('[name="subject"]') || {}).value || '');
                data.append('body_html', bodyField.value || '');
                fetch('?page=template_api', {method:'POST', body:data, credentials:'same-origin'})
                    .then(function (response) { return response.json().then(function (j) { if (!response.ok || !j.ok) throw new Error(j.error || 'Template save failed'); return j; }); })
                    .then(function (result) {
                        if (templateSelect) {
                            var opt = document.createElement('option');
                            opt.value = String(result.id);
                            opt.textContent = name + ' — ' + ((form.querySelector('[name="subject"]') || {}).value || '');
                            opt.selected = true;
                            templateSelect.appendChild(opt);
                        }
                        window.alert('Template saved.');
                    })
                    .catch(function (err) { window.alert(err.message || 'Could not save template.'); });
            });
        }

        editor.innerHTML = bodyField.value || '';
        editor.style.display = 'block';
        bodyField.style.display = 'none';
        document.addEventListener('selectionchange', rememberEditorSelection);
        var toolbar = document.querySelector('.toolbar');
        if (toolbar) toolbar.addEventListener('pointerdown', rememberEditorSelection);
        window.addEventListener('beforeunload', function (event) {
            if (!allowUnload && (editSerial !== savedSerial || Array.from(form.querySelectorAll('input[type=file]')).some(function(f){return f.files && f.files.length;}))) {
                storeLocalDraft(true); event.preventDefault(); event.returnValue = '';
            }
        });
        document.addEventListener('visibilitychange', function () {
            if (document.hidden && !submitting && editSerial !== savedSerial) saveDraft();
        });

        editor.addEventListener('input', function () {
            syncEditorBody();
            scheduleDraftSave();
        });

        editor.addEventListener('paste', function () {
            window.setTimeout(function () {
                syncEditorBody();
                scheduleDraftSave();
            }, 0);
        });

        form.querySelectorAll(
            'input:not([type="file"]), select, textarea'
        ).forEach(function (node) {
            node.addEventListener('input', scheduleDraftSave);
            node.addEventListener('change', scheduleDraftSave);
        });

        var attachments = sharedAttachmentInputs();

        attachments.forEach(function (input) {
            input.addEventListener('change', attachmentStatus);
        });

        if (attachments.length) {
            attachmentStatus();
        }
        document.querySelectorAll('.retained-file input').forEach(function (f) {f.addEventListener('change',attachmentStatus);});

        form.addEventListener('submit', function (event) {
            if (submitting) { event.preventDefault(); return; }
            syncEditorBody();
            var submitter = event.submitter || document.activeElement;
            var saveOnly = submitter && (submitter.name === 'save_draft' || submitter.name === 'new_message');

            if (!attachmentStatus()) {
                event.preventDefault();
                window.alert(
                    'Attachments total 15 MB or more. ' +
                    'Remove one or more files before continuing.'
                );
                return false;
            }

            var doc = document.querySelector(
                'input[name="document_email"]'
            );

            var text =
                (editor.innerText || editor.textContent || '').trim();

            if (
                !saveOnly && text === '' &&
                bodyField.value.trim() === '' &&
                !document.querySelector('.retained-file[data-kind="document"]') &&
                (!doc || !doc.files || !doc.files.length)
            ) {
                event.preventDefault();

                window.alert(
                    'Write/paste a message or upload a document as the email.'
                );

                return false;
            }

            event.preventDefault();
            submitting = true; window.clearTimeout(saveTimer);
            // Native form.submit() omits the clicked button; preserve direct_send explicitly.
            if (submitter && submitter.name) {
                var flag = document.createElement('input'); flag.type = 'hidden';
                flag.name = submitter.name; flag.value = submitter.value; form.appendChild(flag);
            }
            storeLocalDraft(true);
            saveDraft().then(function () {
                // The POST handler also saves synchronously before validating anything.
                syncEditorBody(); allowUnload = true;
                form.querySelectorAll('input[type=file]').forEach(function (f) {if (!f.files || !f.files.length) f.disabled=true;});
                HTMLFormElement.prototype.submit.call(form);
            });
        });

        if (fallback) {
            fallback.value =
                (editor.innerText || editor.textContent || '').trim();
        }

        loadDraft();
    });
})();
