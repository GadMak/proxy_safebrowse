(async () => {
    const currentUrl = window.location.href;
    const currentHostname = new URL(currentUrl).hostname.replace(/^www\./, '');

    // --- Forçage SafeSearch sur Google ---
    if (currentHostname.includes("google.")) {
        const url = new URL(window.location.href);
        if (url.searchParams.get("safe") !== "active") {
            url.searchParams.set("safe", "active");
            window.location.href = url.toString();
            return;
        }
    }

    // --- Masquage dynamique des miniatures adultes (Google Images/Vidéos) ---
    const adultKeywords = ['xvideo', 'porn', 'xxx', 'fuck', 'sex', 'redtube','X-rated', 'xnxx', 'hentai', '18+','Sextape'];
    function hideAdultContent() {
        document.querySelectorAll("img, a, span, div").forEach(el => {
            const content = (el.alt || '') + (el.src || '') + (el.innerText || '');
            const normalized = content.toLowerCase();
            if (adultKeywords.some(word => normalized.includes(word))) {
                el.style.display = 'none';
            }
        });
    }

    if (currentHostname.includes("google.")) {
        setInterval(hideAdultContent, 1500); // vérifie régulièrement (contenu dynamique)
    }

    // --- Gestion de la bannière unique ---
    function removeExistingBanner() {
        const existing = document.getElementById('safebrowse-ai-alert-banner');
        if (existing) existing.remove();
    }

    function updateBanner(status, threats, reason) {
        removeExistingBanner();
        if (status === 'safe' || status === 'whitelisted') return;

        const banner = document.createElement('div');
        banner.id = 'safebrowse-ai-alert-banner';
        banner.className = `safebrowse-ai-alert-banner ${status}`;
        banner.style.transform = 'translateY(-100%)';
        banner.style.transition = 'transform 0.5s ease, opacity 0.5s ease';
        banner.innerHTML = `
            <i class="fas ${status === 'dangerous' ? 'fa-exclamation-triangle' : 'fa-exclamation-circle'}"></i>
            <span class="message-text">SafeBrowse AI : ${status === 'dangerous' ? 'Menaces sévères détectées' : 'Contenu suspect détecté'}${reason ? ' – ' + reason : ''}</span>
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
        setTimeout(() => {
            banner.style.transform = 'translateY(0)';
        }, 100);

        setTimeout(() => {
            if (document.body.contains(banner)) {
                banner.style.transform = 'translateY(-120%)';
                banner.style.opacity = '0';
                setTimeout(() => banner.remove(), 500);
            }
        }, 10000);
    }

    // --- Comptage des pubs ---
    function countAdsOnPage() {
        let adCount = 0;
        adCount += document.querySelectorAll('iframe[src*="ads"], iframe[src*="doubleclick"]').length;
        adCount += document.querySelectorAll('div[id*="ad"], div[class*="ad"]').length;
        chrome.runtime.sendMessage({ action: "adsCount", value: adCount });
    }

    countAdsOnPage();

    // --- Réception du background ---
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === "STATUS_UPDATE") {
            updateBanner(message.status, message.threats, message.reason);
        }
    });

    // --- Statut au chargement ---
    const tabId = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'GET_TAB_ID' }, (res) => resolve(res?.tabId));
    });

    chrome.storage.local.get(null, (all) => {
        const key = tabId ? `threats_${tabId}` : null;
        if (key && all[key]) {
            const d = all[key];
            updateBanner(d.status, d.threats, d.reason);
        }
    });

})();