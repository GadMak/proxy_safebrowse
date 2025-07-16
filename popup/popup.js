document.addEventListener('DOMContentLoaded', async () => {
    const statusCard = document.getElementById('statusCard');
    const statusIcon = document.getElementById('statusIcon');
    const statusMessage = document.getElementById('statusMessage');
    const currentUrlDisplay = document.getElementById('currentUrl');
    const whitelistBtn = document.getElementById('whitelistBtn');
    const reportBtn = document.getElementById('reportBtn');
    const optionsBtn = document.getElementById('optionsBtn');

    const phishingStatus = document.getElementById('phishing-status');
    const threatsStatus = document.getElementById('threats-status');
    const vulnerabilitiesStatus = document.getElementById('vulnerabilities-status');
    const adsCount = document.getElementById('ads-count');
    const viewDetailsContainer = document.getElementById('viewDetailsContainer');

    let activeTab, threatData = null, siteToCheck = null;

    function normalizeDomain(domain) {
        return domain.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/$/, '').toLowerCase();
    }

    async function getThreatData(tabId, url) {
        const allThreats = await chrome.storage.local.get(null);
        let normDomain = url ? normalizeDomain(url).split('/')[0] : null;

        // 1. Cherche par tabId
        if (tabId && allThreats[`threats_${tabId}`]) {
            return allThreats[`threats_${tabId}`];
        }
        // 2. Cherche par domaine pur
        if (normDomain && allThreats[`threats_${normDomain}`]) {
            return allThreats[`threats_${normDomain}`];
        }
        // 3. Recherche large (optionnelle)
        if (normDomain) {
            const found = Object.values(allThreats).find(val =>
                val.url && val.url.includes(normDomain)
            );
            if (found) return found;
        }
        return null;
    }

    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        activeTab = tabs[0];
        let urlToCheck = activeTab?.url;

        // Cas 1 : Page de blocage SafeBrowse
        if (urlToCheck && urlToCheck.startsWith("chrome-extension://") && urlToCheck.includes("phish_block")) {
            const params = new URLSearchParams(new URL(urlToCheck).search);
            siteToCheck = params.get("site");
            currentUrlDisplay.textContent = siteToCheck || urlToCheck;
        } else if (urlToCheck) {
            siteToCheck = urlToCheck;
            currentUrlDisplay.textContent = urlToCheck;
        }

        // Recherche intelligente
        let normDomain = siteToCheck ? normalizeDomain(siteToCheck).split('/')[0] : null;
        threatData = await getThreatData(activeTab?.id, siteToCheck);

        // ---- AFFICHAGE DU RÉSUMÉ ----
        if (threatData) {
            let { status, threats = [] } = threatData;

            // -------- DÉTECTION ULTRA-FIABLE ----------
            // On considère "phishing" détecté si threats contient le mot "phishing" (sous n'importe quelle forme)
            const hasPhishing = (threats || []).some(t =>
                t.toLowerCase().includes("phishing")
            );
            // Menace si "dangerous" ou "warning"
            const hasThreats = status === 'dangerous' || status === 'warning';
            const hasVulnerabilities = (threats || []).some(t =>
                t.toLowerCase().includes("xss") ||
                t.toLowerCase().includes("clé sensible") ||
                t.toLowerCase().includes("vulnérabilité")
            );
            const adCount = 0;

            phishingStatus.textContent = hasPhishing ? "Oui" : "Non";
            threatsStatus.textContent = hasThreats ? "Oui" : "Non";
            vulnerabilitiesStatus.textContent = hasVulnerabilities ? "Oui" : "Non";
            adsCount.textContent = adCount.toString();

            // Affichage visuel
            statusCard.className = 'status-card';
            statusIcon.parentElement.className = 'status-icon-container';

            if (hasPhishing) {
                statusCard.className = 'status-card status-phishing-card';
                statusIcon.className = 'fas fa-skull-crossbones status-icon';
                statusIcon.parentElement.className = 'status-phishing-icon-container';
                statusMessage.textContent = "🚨 ATTENTION : site de phishing détecté !";
                statusMessage.style.fontWeight = 'bold';
                statusMessage.style.color = '#c82333';

                if (viewDetailsContainer) {
                    viewDetailsContainer.style.display = 'block';
                    viewDetailsContainer.innerHTML = `<span style="color:#c82333;font-weight:bold;">Ce site a été signalé comme site de phishing. Évitez d’entrer des informations personnelles !</span>`;
                }
                return;
            }

            switch (status) {
                case 'safe':
                    statusCard.classList.add('status-safe-card');
                    statusIcon.className = 'fas fa-check-circle status-icon';
                    statusIcon.parentElement.classList.add('status-safe-icon-container');
                    statusMessage.textContent = "✅ Cette page semble sûre.";
                    break;
                case 'dangerous':
                    statusCard.classList.add('status-dangerous-card');
                    statusIcon.className = 'fas fa-exclamation-triangle status-icon';
                    statusIcon.parentElement.classList.add('status-dangerous-icon-container');
                    statusMessage.textContent = "🛑 Menaces sévères détectées.";
                    break;
                case 'warning':
                    statusCard.classList.add('status-warning-card');
                    statusIcon.className = 'fas fa-exclamation-circle status-icon';
                    statusIcon.parentElement.classList.add('status-warning-icon-container');
                    statusMessage.textContent = "⚠️ Contenu suspect détecté.";
                    break;
                case 'whitelisted':
                    statusCard.classList.add('status-whitelisted-card');
                    statusIcon.className = 'fas fa-shield-alt status-icon';
                    statusIcon.parentElement.classList.add('status-whitelisted-icon-container');
                    statusMessage.textContent = "🔐 Ce site est dans la liste blanche.";
                    break;
                default:
                    statusCard.classList.add('status-info-card');
                    statusIcon.className = 'fas fa-question-circle status-icon';
                    statusIcon.parentElement.classList.add('status-info-icon-container');
                    statusMessage.textContent = "Statut inconnu.";
            }

            if (viewDetailsContainer) {
                viewDetailsContainer.style.display = 'none';
            }
        } else {
            // Aucune donnée pour ce site : état analyse en cours
            statusMessage.textContent = "⏳ Analyse en cours...";
            statusIcon.className = 'fas fa-spinner fa-spin status-icon';
            phishingStatus.textContent = "-";
            threatsStatus.textContent = "-";
            vulnerabilitiesStatus.textContent = "-";
            adsCount.textContent = "0";
        }
    } catch (error) {
        console.error("Erreur récupération popup :", error);
        statusMessage.textContent = "❌ Erreur d'analyse.";
        phishingStatus.textContent = "-";
        threatsStatus.textContent = "-";
        vulnerabilitiesStatus.textContent = "-";
        adsCount.textContent = "0";
    }

    whitelistBtn.addEventListener('click', async () => {
        if (!siteToCheck) return;
        let domain = siteToCheck;
        if (domain.includes("/")) {
            domain = domain.split("/")[0];
        }
        const { userWhitelist } = await chrome.storage.sync.get("userWhitelist");
        const updatedList = Array.isArray(userWhitelist) ? [...new Set([...userWhitelist, domain])] : [domain];
        await chrome.storage.sync.set({ userWhitelist: updatedList });
        chrome.runtime.sendMessage({ type: 'WHITELIST_UPDATED' });
        if (activeTab?.id) chrome.tabs.reload(activeTab.id);
    });

    reportBtn.addEventListener('click', () => {
        alert("🛠️ Fonction de signalement à implémenter.");
    });

    optionsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });
});