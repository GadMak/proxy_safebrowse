document.addEventListener('DOMContentLoaded', async () => {
    // --- Références DOM ---
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

    // --- UTIL ---
    function normalizeDomain(domain) {
        return domain.replace(/^https?:\/\//i, '')
            .replace(/^www\./i, '')
            .replace(/\/.*$/, '')
            .toLowerCase();
    }

    try {
        // 1. Onglet actif
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        activeTab = tabs[0];
        let urlToCheck = activeTab?.url;

        // 2. Page de blocage ou page normale ?
        if (urlToCheck && urlToCheck.startsWith("chrome-extension://") && urlToCheck.includes("phish_block")) {
            const params = new URLSearchParams(new URL(urlToCheck).search);
            siteToCheck = params.get("site") || urlToCheck;
            currentUrlDisplay.textContent = siteToCheck;
        } else if (urlToCheck) {
            siteToCheck = urlToCheck;
            currentUrlDisplay.textContent = urlToCheck;
        }

        // 3. Lecture du statut (clé threats_<tabId>)
        let threatsKey = activeTab?.id ? `threats_${activeTab.id}` : null;
        let threatObj = threatsKey ? (await chrome.storage.local.get(threatsKey))[threatsKey] : null;
        threatData = threatObj || null;

        // 4. Affichage du résumé d’analyse
        if (threatData) {
            const threats = Array.isArray(threatData.threats) ? threatData.threats.map(t => t.toLowerCase()) : [];
            const status = threatData.status || "safe";
            const ads = threatData.adsCount !== undefined ? threatData.adsCount : (threatData.ads || 0);
            const isVuln = threats.includes("vulnerability") || threats.includes("vulnérabilité") || threatData.hasVulnerabilities === true;
            const isPhishing = threats.includes("phishing");
            const isThreat = (status === 'dangerous') && !isPhishing && !isVuln;
            const hasAds = ads && ads > 0;

            phishingStatus.textContent = isPhishing ? "Oui" : "Non";
            threatsStatus.textContent = (isPhishing || isThreat) ? "Oui" : "Non";
            vulnerabilitiesStatus.textContent = isVuln ? "Oui" : "Non";
            adsCount.textContent = hasAds ? ads.toString() : "0";

            // Affichage de l’icône et couleur
            statusCard.className = 'status-card';
            statusIcon.parentElement.className = 'status-icon-container';
            statusMessage.style.color = '';
            statusMessage.style.fontWeight = 'bold';

            if (isPhishing) {
                statusCard.classList.add('status-dangerous-card');
                statusIcon.className = 'fas fa-skull-crossbones status-icon';
                statusIcon.parentElement.classList.add('status-dangerous-icon-container');
                statusMessage.textContent = "🚨 ATTENTION : site de phishing détecté !";
                statusMessage.style.color = '#c82333';
            } else if (isThreat) {
                statusCard.classList.add('status-warning-card');
                statusIcon.className = 'fas fa-exclamation-triangle status-icon';
                statusIcon.parentElement.classList.add('status-warning-icon-container');
                statusMessage.textContent = "⚠️ Menaces sévères détectées.";
                statusMessage.style.color = '#d35400';
            } else if (isVuln) {
                statusCard.classList.add('status-warning-card');
                statusIcon.className = 'fas fa-bug status-icon';
                statusIcon.parentElement.classList.add('status-warning-icon-container');
                statusMessage.textContent = "⚠️ Vulnérabilités détectées.";
                statusMessage.style.color = '#d35400';
            } else if (hasAds) {
                statusCard.classList.add('status-warning-card');
                statusIcon.className = 'fas fa-ad status-icon';
                statusIcon.parentElement.classList.add('status-warning-icon-container');
                statusMessage.textContent = "⚠️ Publicités détectées sur la page.";
                statusMessage.style.color = '#e67e22';
            } else if (status === 'whitelisted') {
                statusCard.classList.add('status-whitelisted-card');
                statusIcon.className = 'fas fa-shield-alt status-icon';
                statusIcon.parentElement.classList.add('status-whitelisted-icon-container');
                statusMessage.textContent = "🔐 Ce site est dans la liste blanche.";
                statusMessage.style.color = '#2196F3';
            } else {
                statusCard.classList.add('status-safe-card');
                statusIcon.className = 'fas fa-check-circle status-icon';
                statusIcon.parentElement.classList.add('status-safe-icon-container');
                statusMessage.textContent = "✅ Cette page semble sûre.";
                statusMessage.style.color = '#4CAF50';
            }
            if (viewDetailsContainer) viewDetailsContainer.style.display = 'none';
        } else {
            // Analyse en cours
            statusCard.className = 'status-card';
            statusIcon.className = 'fas fa-spinner fa-spin status-icon';
            statusMessage.textContent = "⏳ Analyse en cours...";
            phishingStatus.textContent = "-";
            threatsStatus.textContent = "-";
            vulnerabilitiesStatus.textContent = "-";
            adsCount.textContent = "0";
            if (viewDetailsContainer) viewDetailsContainer.style.display = 'none';
        }
    } catch (error) {
        console.error("Erreur récupération popup :", error);
        statusMessage.textContent = "❌ Erreur d'analyse.";
        phishingStatus.textContent = "-";
        threatsStatus.textContent = "-";
        vulnerabilitiesStatus.textContent = "-";
        adsCount.textContent = "0";
        if (viewDetailsContainer) viewDetailsContainer.style.display = 'none';
    }

    // --- BOUTON "AJOUTER À LA LISTE BLANCHE" ---
    whitelistBtn.addEventListener('click', async () => {
        if (!siteToCheck) return;
        let domain = siteToCheck;
        if (domain.includes("/")) {
            try {
                domain = (new URL(domain)).hostname || domain;
            } catch {
                domain = domain.split("/")[0];
            }
        }
        domain = normalizeDomain(domain);
        const { userWhitelist } = await chrome.storage.sync.get("userWhitelist");
        const updatedList = Array.isArray(userWhitelist) ? [...new Set([...userWhitelist, domain])] : [domain];
        await chrome.storage.sync.set({ userWhitelist: updatedList });
        chrome.runtime.sendMessage({ type: 'WHITELIST_UPDATED' });
        if (activeTab?.id) chrome.tabs.reload(activeTab.id);
    });

    // --- BOUTON SIGNALER ---
    reportBtn.addEventListener('click', () => {
        alert("🛠️ Fonction de signalement à implémenter.");
    });

    // --- BOUTON OPTIONS ---
    optionsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });
});