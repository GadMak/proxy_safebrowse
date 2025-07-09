(async () => {
    const currentUrl = window.location.href;
    const currentHostname = new URL(currentUrl).hostname.replace(/^www\./, '');

    const tabId = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, (res) => resolve(res?.tabId));
    });

    const settings = await new Promise((resolve) => {
        chrome.storage.sync.get({
            enablePhishing: true,
            enableThreats: true,
            enableVulnerabilities: true,
            enableAdultBlocking: true,
            enableAdBlocking: true,
            userWhitelist: []
        }, resolve);
    });

    // Vérifier la liste blanche
    const normalizedWhitelist = (settings.userWhitelist || []).map(domain => domain.replace(/^www\./, ''));
    if (normalizedWhitelist.includes(currentHostname)) {
        console.log(`[SafeBrowse AI - CA] ${currentHostname} est dans la liste blanche. Analyse ignorée.`);
        chrome.storage.local.set({
            [`threats_${tabId}`]: {
                status: 'whitelisted',
                url: currentUrl,
                threats: []
            }
        });
        chrome.runtime.sendMessage({
            type: "UPDATE_ICON",
            status: "safe",
            tabId
        });
        return;
    }

    const threats = [];

    function addThreat(threatsArray, element, type, description) {
        console.warn(`[SafeBrowse AI - CA] Menace [${type}] : ${description}`);
        if (element && !['body', 'html'].includes(element.tagName?.toLowerCase())) {
            element.classList.add('safebrowse-ai-suspicious-element');
            element.title = `Avertissement SafeBrowse AI : ${description}`;
        }
        threatsArray.push({ type, description, elementTag: element?.tagName || 'N/A' });
    }

    function detectPhishingThreats() {
        const threats = [];
        document.querySelectorAll('form').forEach(form => {
            const hasPassword = form.querySelector('input[type="password"]');
            const hasEmail = form.querySelector('input[type="email"]');
            if ((hasPassword || hasEmail) && location.protocol !== 'https:') {
                addThreat(threats, form, 'INSECURE_FORM', 'Formulaire non sécurisé sur HTTP.');
            }
            const action = form.getAttribute('action');
            if (action) {
                try {
                    const targetUrl = new URL(action, location.href);
                    if (targetUrl.hostname !== location.hostname && !action.startsWith('/') && !action.startsWith('#')) {
                        addThreat(threats, form, 'FORM_EXTERNAL_ACTION', `Formulaire envoie vers domaine externe : ${targetUrl.hostname}`);
                    }
                } catch (e) {
                    console.error("[SafeBrowse AI - CA] Erreur URL action:", e);
                }
            }
        });
        return threats;
    }

    function detectGeneralWebThreats() {
        const threats = [];
        document.querySelectorAll('script').forEach(script => {
            const src = script.getAttribute('src');
            const code = script.textContent;
            if (src) {
                try {
                    const url = new URL(src, location.href);
                    if (url.hostname !== location.hostname) {
                        addThreat(threats, script, 'EXTERNAL_SCRIPT', `Script externe : ${url.hostname}`);
                    }
                } catch {}
            } else if (code && code.length > 100 && code.includes('eval')) {
                addThreat(threats, script, 'INLINE_SUSPICIOUS_SCRIPT', 'Script inline avec eval.');
            }
        });
        return threats;
    }

    function detectWebAppVulnerabilities() {
        const threats = [];
        const keys = ['token', 'api_key', 'password', 'jwt', 'session_id'];
        keys.forEach(key => {
            if (localStorage.getItem(key) || sessionStorage.getItem(key)) {
                addThreat(threats, document.body, 'SENSITIVE_STORAGE', `Clé sensible : ${key}`);
            }
        });
        return threats;
    }

    if (settings.enablePhishing) threats.push(...detectPhishingThreats());
    if (settings.enableThreats) threats.push(...detectGeneralWebThreats());
    if (settings.enableVulnerabilities) threats.push(...detectWebAppVulnerabilities());

    const isSevere = threats.some(t => [
        'INSECURE_FORM', 'FORM_EXTERNAL_ACTION', 'SENSITIVE_STORAGE'
    ].includes(t.type));

    const status = threats.length === 0
        ? 'safe'
        : isSevere ? 'dangerous' : 'warning';

    chrome.storage.local.set({
        [`threats_${tabId}`]: {
            status,
            url: currentUrl,
            threats: threats.map(t => t.description)
        }
    });

    const existing = document.getElementById('safebrowse-ai-alert-banner');
    if (existing) existing.remove();

    if (status !== 'safe') {
        const banner = document.createElement('div');
        banner.id = 'safebrowse-ai-alert-banner';
        banner.className = `safebrowse-ai-alert-banner ${status}`;
        banner.style.transform = 'translateY(-100%)';
        banner.style.transition = 'transform 0.5s ease, opacity 0.5s ease';
        banner.innerHTML = `
            <i class="fas ${status === 'dangerous' ? 'fa-exclamation-triangle' : 'fa-exclamation-circle'}"></i>
            <span class="message-text">SafeBrowse AI : ${status === 'dangerous' ? 'Menaces sévères' : 'Contenu suspect'} détecté.</span>
            <button class="close-btn" title="Fermer l’alerte">&times;</button>
        `;

        banner.querySelector('.close-btn').addEventListener('click', () => {
            banner.style.transform = 'translateY(-120%)';
            banner.style.opacity = '0';
            setTimeout(() => banner.remove(), 500);
        });

        if (!document.getElementById('safebrowse-banner-style')) {
            const style = document.createElement('style');
            style.id = 'safebrowse-banner-style';
            style.textContent = `
                .safebrowse-ai-alert-banner {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    z-index: 999999;
                    padding: 12px 20px;
                    font-weight: bold;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    color: white;
                    font-family: sans-serif;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    opacity: 1;
                }
                .safebrowse-ai-alert-banner.dangerous {
                    background-color: #f44336;
                }
                .safebrowse-ai-alert-banner.warning {
                    background-color: #ffc107;
                    color: black;
                }
                .safebrowse-ai-alert-banner .message-text {
                    flex-grow: 1;
                    margin-left: 10px;
                }
                .safebrowse-ai-alert-banner .close-btn {
                    background: transparent;
                    border: none;
                    color: inherit;
                    font-size: 20px;
                    cursor: pointer;
                    margin-left: 10px;
                }
            `;
            document.head.appendChild(style);
        }

        document.body.prepend(banner);

        // Slide-in animation
        setTimeout(() => {
            banner.style.transform = 'translateY(0)';
        }, 100);

        // Fermeture automatique après 10 secondes
        setTimeout(() => {
            if (document.body.contains(banner)) {
                banner.style.transform = 'translateY(-120%)';
                banner.style.opacity = '0';
                setTimeout(() => banner.remove(), 500);
            }
        }, 10000); // 10 000 ms = 10 secondes
    }

    chrome.runtime.sendMessage({
        type: "UPDATE_ICON",
        status,
        tabId
    });
})();
