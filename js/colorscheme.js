const darkStyleSheets = document.querySelectorAll('[media="screen and (prefers-color-scheme: dark)"]');

if (localStorage.getItem("pref-theme") === "dark") {
    darkStyleSheets.forEach(element => {
        element.media = "screen";
    });
} else if (localStorage.getItem("pref-theme") === "light") {
    darkStyleSheets.forEach(element => {
        element.media = "not all";
    });
} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    darkStyleSheets.forEach(element => {
        element.media = "screen and (prefers-color-scheme: dark)";
    });
}

function setColorSchemePreference(newPref) {
    if (newPref === "auto") {
        darkStyleSheets.forEach(element => {
            element.media = "screen and (prefers-color-scheme: dark)";
        });
        localStorage.removeItem("pref-theme");
        document.querySelector("input[name='theme-toggle'][value='auto']").checked = true;
    } else if (newPref === "light") {
        darkStyleSheets.forEach(element => {
            element.media = "not all";
        });
        localStorage.setItem("pref-theme", 'light');
        document.querySelector("input[name='theme-toggle'][value='light']").checked = true;
    } else if (newPref === "dark") {
        darkStyleSheets.forEach(element => {
            element.media = "screen";
        });
        localStorage.setItem("pref-theme", 'dark');
        document.querySelector("input[name='theme-toggle'][value='dark']").checked = true;
    }
}