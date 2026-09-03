(function () {
    'use strict';

    var WARN_BYTES = 12 * 1024 * 1024;
    var STOP_BYTES = 15 * 1024 * 1024;
    var saveTimer = null;
    var loadingDraft = false;

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

        editor.focus();
        document.execCommand(cmd, false, null);
        syncEditorBody();
        scheduleDraftSave();
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
        if (loadingDraft) return;

        var form = byId('composeForm');

        if (!form) return;

        var acting = form.querySelector('[name="acting_for"]');

        draftStatus('Saving draft…', false);

        fetch(
            '?page=draft_api&acting_for=' +
                encodeURIComponent(acting ? acting.value : ''),
            {
                method: 'POST',
                body: draftData(),
                credentials: 'same-origin'
            }
        )
        .then(function (response) {
            if (!response.ok) throw new Error('Draft save failed');
            return response.json();
        })
        .then(function (result) {
            if (!result.ok) throw new Error('Draft save failed');

            draftStatus(
                'Draft saved automatically at ' +
                new Date().toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit'
                }),
                false
            );
        })
        .catch(function () {
            draftStatus(
                'Draft could not be saved — keep this page open until connection returns.',
                true
            );
        });
    }

    function scheduleDraftSave() {
        if (loadingDraft) return;

        window.clearTimeout(saveTimer);
        saveTimer = window.setTimeout(saveDraft, 900);
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
            var d = result.draft;

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
        });
    }

    function attachmentTotal() {
        var input = document.querySelector(
            'input[name="attachments[]"]'
        );

        if (!input || !input.files) return 0;

        var total = 0;

        Array.prototype.forEach.call(input.files, function (file) {
            total += file.size || 0;
        });

        return total;
    }

    function attachmentStatus() {
        var input = document.querySelector(
            'input[name="attachments[]"]'
        );

        if (!input) return true;

        var status = byId('attachmentStatus');

        if (!status) {
            status = document.createElement('div');
            status.id = 'attachmentStatus';
            status.style.marginTop = '8px';
            status.style.padding = '10px';
            status.style.borderRadius = '7px';

            input.parentNode.insertBefore(
                status,
                input.nextSibling
            );
        }

        var total = attachmentTotal();
        var count = input.files ? input.files.length : 0;

        if (!count) {
            status.textContent =
                'No attachments selected. Combined maximum: 15 MB.';
            status.style.background = '#edf0f4';
            status.style.color = '#444';
            return true;
        }

        if (total >= STOP_BYTES) {
            status.innerHTML =
                '<b>STOP:</b> ' + count +
                ' attachment(s), ' + fmtBytes(total) +
                ' combined. Maximum allowed is 15 MB. ' +
                'Remove one or more files before continuing.';

            status.style.background = '#fdeaea';
            status.style.color = '#8f2020';
            return false;
        }

        if (total >= WARN_BYTES) {
            status.innerHTML =
                '<b>Warning:</b> ' + count +
                ' attachment(s), ' + fmtBytes(total) +
                ' combined. You are approaching the 15 MB hard limit.';

            status.style.background = '#fff3ca';
            status.style.color = '#705600';
            return true;
        }

        status.innerHTML =
            '<b>' + count + '</b> attachment(s), ' +
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

        editor.innerHTML = bodyField.value || '';
        editor.style.display = 'block';
        bodyField.style.display = 'none';

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

        var attachments = document.querySelector(
            'input[name="attachments[]"]'
        );

        if (attachments) {
            attachments.addEventListener(
                'change',
                attachmentStatus
            );

            attachmentStatus();
        }

        form.addEventListener('submit', function (event) {
            syncEditorBody();

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
                text === '' &&
                bodyField.value.trim() === '' &&
                (!doc || !doc.files || !doc.files.length)
            ) {
                event.preventDefault();

                window.alert(
                    'Write/paste a message or upload a document as the email.'
                );

                return false;
            }

            saveDraft();
        });

        if (fallback) {
            fallback.value =
                (editor.innerText || editor.textContent || '').trim();
        }

        loadDraft();
    });
})();
