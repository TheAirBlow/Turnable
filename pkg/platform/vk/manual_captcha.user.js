// ==UserScript==
// @name         Turnable - VK Token Capture
// @namespace    turnable
// @version      1.0
// @description  Captures VK Calls tokens for Turnable
// @match        https://vk.com/call/join/*
// @grant        unsafeWindow
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    const SERVER = 'http://localhost:1984';

    let _serverAlive = false;
    let _done = false;

    function extractFormParam(body, key) {
        if (!body || typeof body !== 'string') return '';
        for (const pair of body.split('&')) {
            const idx = pair.indexOf('=');
            if (idx < 0) continue;
            try {
                if (decodeURIComponent(pair.slice(0, idx)) === key)
                    return decodeURIComponent(pair.slice(idx + 1));
            } catch (e) {}
        }
        return '';
    }

    function sendTokens(messagesToken, anonToken) {
        if (_done || !anonToken) return;
        _done = true;
        window.location.replace(
            SERVER + '/done?messages=' + encodeURIComponent(messagesToken || '') +
            '&calls=' + encodeURIComponent(anonToken)
        );
    }

    const origFetch = unsafeWindow.fetch.bind(unsafeWindow);
    unsafeWindow.fetch = function (...args) {
        if (!_serverAlive) return origFetch(...args);

        const [input, init] = args;
        const urlStr = typeof input === 'string' ? input : (input && input.url ? input.url : '');

        if (urlStr.includes('calls.getAnonymousToken')) {
            const bodyArg = init && init.body;
            const bodyText = bodyArg instanceof URLSearchParams
                ? bodyArg.toString()
                : (typeof bodyArg === 'string' ? bodyArg : '');

            return origFetch(...args).then(response => {
                return response.clone().json().then(data => {
                    if (data && data.response && data.response.token)
                        sendTokens(extractFormParam(bodyText, 'access_token'), data.response.token);
                    return response;
                }).catch(() => response);
            });
        }

        return origFetch(...args);
    };

    const origXHROpen = unsafeWindow.XMLHttpRequest.prototype.open;
    unsafeWindow.XMLHttpRequest.prototype.open = function (...args) {
        if (typeof args[1] === 'string') this._captureUrl = args[1];
        return origXHROpen.apply(this, args);
    };

    const origXHRSend = unsafeWindow.XMLHttpRequest.prototype.send;
    unsafeWindow.XMLHttpRequest.prototype.send = function (body) {
        if (_serverAlive && this._captureUrl && this._captureUrl.includes('calls.getAnonymousToken')) {
            const sentBody = typeof body === 'string' ? body : (body instanceof URLSearchParams ? body.toString() : '');
            this.addEventListener('load', () => {
                try {
                    const data = JSON.parse(this.responseText);
                    if (data && data.response && data.response.token)
                        sendTokens(extractFormParam(sentBody, 'access_token'), data.response.token);
                } catch (e) {}
            });
        }
        return origXHRSend.apply(this, arguments);
    };

    fetch(SERVER + '/ping', { signal: AbortSignal.timeout(2000) })
        .then(r => { if (r.ok) { _serverAlive = true; setupAutoJoin(); } })
        .catch(() => {});

    function setupAutoJoin() {
        const observer = new MutationObserver(tryAutoJoin);
        const observe = () => {
            if (document.documentElement)
                observer.observe(document.documentElement, { subtree: true, childList: true });
        };

        observe();
        document.addEventListener('DOMContentLoaded', () => { observe(); tryAutoJoin(); });
        tryAutoJoin();
    }

    let _joined = false;
    function tryAutoJoin() {
        if (_joined) return;

        if (document.querySelector('[data-testid="calls_preview_join_button"]')) {
            _joined = true;
            showLoggedInWarning();
            return;
        }

        const anonBtn = document.querySelector('[data-testid="calls_preview_join_button_anonym"]');
        const input = document.querySelector('input[type="text"][maxlength="25"]');
        if (!anonBtn || !input) return;

        _joined = true;

        try {
            const setter = Object.getOwnPropertyDescriptor(unsafeWindow.HTMLInputElement.prototype, 'value').set;
            setter.call(input, '123');
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (e) {
            input.value = '123';
        }

        const start = Date.now();
        function waitAndClick() {
            const btn = document.querySelector('[data-testid="calls_preview_join_button_anonym"]');
            if (btn && !btn.disabled) {
                btn.click();
                return;
            }
            if (Date.now() - start < 3000) setTimeout(waitAndClick, 100);
        }

        setTimeout(waitAndClick, 150);
    }

    function showLoggedInWarning() {
        function render() {
            if (!document.body) { setTimeout(render, 50); return; }

            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:sans-serif';
            overlay.innerHTML = `
                <div style="background:#fff;padding:32px 40px;border-radius:16px;max-width:420px;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.3)">
                    <div style="font-size:52px;line-height:1">⚠️</div>
                    <h2 style="margin:16px 0 8px;color:#1a1a1a !important;font-size:20px">You are logged in</h2>
                    <p style="color:#555;margin:0 0 4px;line-height:1.5">For the safety of your account, an anonymous session is required.</p>
                    <p style="color:#555;margin:0 0 4px;line-height:1.5">Please <b>log out</b> or open this page in an <b>Incognito window</b>.</p>
                </div>`;
            document.body.appendChild(overlay);
        }
        render();
    }
})();
