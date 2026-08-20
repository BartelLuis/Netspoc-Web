(function (window, document) {
    'use strict';

    var STORAGE_KEY = 'policyweb-theme';
    var DARK_QUERY = '(prefers-color-scheme: dark)';
    var mediaQuery = window.matchMedia ? window.matchMedia(DARK_QUERY) : null;
    var listeners = [];
    var currentTheme;

    function isTheme(value) {
        return value === 'light' || value === 'dark';
    }

    function readStoredTheme() {
        var value;

        try {
            value = window.localStorage.getItem(STORAGE_KEY);
        }
        catch (ignore) {
            return null;
        }

        return isTheme(value) ? value : null;
    }

    function systemTheme() {
        return mediaQuery && mediaQuery.matches ? 'dark' : 'light';
    }

    function resolvedTheme() {
        return readStoredTheme() || systemTheme();
    }

    function setDocumentTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);

        if (document.body) {
            document.body.setAttribute('data-theme', theme);
        }
    }

    function notify(theme) {
        var snapshot = listeners.slice(0);
        var i;

        for (i = 0; i < snapshot.length; i += 1) {
            snapshot[i](theme);
        }
    }

    function apply(theme) {
        var changed;

        if (!isTheme(theme)) {
            theme = resolvedTheme();
        }

        changed = currentTheme !== theme;
        currentTheme = theme;
        setDocumentTheme(theme);

        if (changed) {
            notify(theme);
        }

        return theme;
    }

    function store(theme) {
        try {
            window.localStorage.setItem(STORAGE_KEY, theme);
        }
        catch (ignore) {
            // The visual switch still works when storage is unavailable.
        }
    }

    function set(theme) {
        if (!isTheme(theme)) {
            throw new TypeError('Theme must be "light" or "dark"');
        }

        store(theme);
        return apply(theme);
    }

    function toggle() {
        return set(currentTheme === 'dark' ? 'light' : 'dark');
    }

    function useSystemPreference() {
        try {
            window.localStorage.removeItem(STORAGE_KEY);
        }
        catch (ignore) {
            // Applying the current system preference still works without storage.
        }

        return apply(systemTheme());
    }

    function onChange(listener) {
        if (typeof listener !== 'function') {
            throw new TypeError('Theme listener must be a function');
        }

        listeners.push(listener);

        return function () {
            var remaining = [];
            var i;

            for (i = 0; i < listeners.length; i += 1) {
                if (listeners[i] !== listener) {
                    remaining.push(listeners[i]);
                }
            }
            listeners = remaining;
        };
    }

    function onSystemThemeChange(event) {
        if (readStoredTheme() === null) {
            apply(event.matches ? 'dark' : 'light');
        }
    }

    function onStorageChange(event) {
        if (event.key === STORAGE_KEY) {
            apply(isTheme(event.newValue) ? event.newValue : systemTheme());
        }
    }

    function toggleText(theme) {
        return theme === 'dark' ? 'Light Mode' : 'Dark Mode';
    }

    function syncToggle(button, theme) {
        var label = toggleText(theme);
        var labelNode = button.querySelector ?
            button.querySelector('[data-policyweb-theme-label]') : null;

        button.setAttribute('data-theme-current', theme);
        button.setAttribute('aria-label', label + ' aktivieren');
        button.setAttribute('title', label + ' aktivieren');

        if (button.getAttribute('data-policyweb-theme-toggle') !== 'icon-only') {
            if (labelNode) {
                labelNode.textContent = label;
            }
            else {
                button.textContent = label;
            }
        }
    }

    function findToggles(root) {
        if (!root.querySelectorAll) {
            return [];
        }

        return root.querySelectorAll(
            '[data-policyweb-theme-toggle], .pw-theme-toggle'
        );
    }

    function syncToggles(theme) {
        var buttons = findToggles(document);
        var i;

        for (i = 0; i < buttons.length; i += 1) {
            syncToggle(buttons[i], theme);
        }
    }

    function bindToggles(root) {
        var buttons = findToggles(root || document);
        var i;

        for (i = 0; i < buttons.length; i += 1) {
            if (!buttons[i]._policyWebThemeBound) {
                buttons[i]._policyWebThemeBound = true;
                buttons[i].addEventListener('click', toggle);
            }
            syncToggle(buttons[i], currentTheme);
        }
    }

    window.PolicyWebTheme = {
        storageKey: STORAGE_KEY,
        get: function () {
            return currentTheme;
        },
        getStored: readStoredTheme,
        isDark: function () {
            return currentTheme === 'dark';
        },
        set: set,
        toggle: toggle,
        useSystemPreference: useSystemPreference,
        onChange: onChange,
        apply: apply,
        bindToggles: bindToggles,
        syncToggles: syncToggles
    };

    apply(resolvedTheme());
    onChange(syncToggles);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            setDocumentTheme(currentTheme);
            bindToggles(document);
        });
    }
    else {
        bindToggles(document);
    }

    if (mediaQuery) {
        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', onSystemThemeChange);
        }
        else if (mediaQuery.addListener) {
            mediaQuery.addListener(onSystemThemeChange);
        }
    }

    if (window.addEventListener) {
        window.addEventListener('storage', onStorageChange);
    }
}(window, document));
