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

    let activeTab;
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        activeTab = tabs[0];

        if (activeTab?.url) {
            currentUrlDisplay.textContent = activeTab.url;

            const allThreats = await chrome.storage.local.get(null);
            const threatsEntry = Object.entries(allThreats).find(
                ([key, value]) =>
                    key.startsWith('threats_') &&
                    value.url === activeTab.url
            );

            if (threatsEntry) {
                const threatData = threatsEntry[1];
                let { status, threats = [] } = threatData;

                // Analyse intelligente
                const hasPhishing = threats.some(t => t.toLowerCase().includes("phishing"));
                const hasThreats = threats.some(t => t.toLowerCase().includes("script") || t.toLowerCase().includes("contenu"));
                const hasVulnerabilities = threats.some(t => t.toLowerCase().includes("xss") || t.toLowerCase().includes("clé sensible"));
                const adCount = document.querySelectorAll('iframe[src*="ads"], script[src*="ads"], div[class*="ads"], a[href*="ads"]').length;

                phishingStatus.textContent = hasPhishing ? "Oui" : "Non";
                threatsStatus.textContent = hasThreats ? "Oui" : "Non";
                vulnerabilitiesStatus.textContent = hasVulnerabilities ? "Oui" : "Non";
                adsCount.textContent = adCount.toString();

                const isReallySafe = !hasPhishing && !hasThreats && !hasVulnerabilities && adCount === 0;
                if (isReallySafe) {
                    status = 'safe';
                }

                // Affichage visuel
                statusCard.className = 'status-card';
                statusIcon.parentElement.className = 'status-icon-container';

                if (hasPhishing) {
                    statusCard.className = 'status-card status-phishing-card';
                    statusIcon.className = 'fas fa-skull-crossbones status-icon'; // ou autre icône choquante
                    statusIcon.parentElement.className = 'status-phishing-icon-container';
                    statusMessage.textContent = "🚨 ATTENTION : site de phishing détecté !";
                    statusMessage.style.fontWeight = 'bold';
                    statusMessage.style.color = '#c82333'; // rouge vif
                
                    // Optionnel : lien pour en savoir plus ou signaler
                    if (viewDetailsContainer) {
                        viewDetailsContainer.style.display = 'block';
                        viewDetailsContainer.innerHTML = `<span style="color:#c82333;font-weight:bold;">Ce site a été signalé comme site de phishing. Évitez d’entrer des informations personnelles !</span>`;
                    }
                    return; // on arrête là pour prioriser l’affichage phishing
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

                // Lien vers threats.html uniquement si des menaces sont détectées
                if (!isReallySafe && viewDetailsContainer) {
                    const encodedThreats = encodeURIComponent(btoa(JSON.stringify(threats)));
                    const encodedSource = encodeURIComponent(activeTab.url);
                    const threatPageUrl = `../pages/threats.html?data=${encodedThreats}&source=${encodedSource}`;
                  
                    viewDetailsContainer.style.display = 'block';
                    viewDetailsContainer.innerHTML = ''; // Réinitialiser
                  
                    const a = document.createElement('a');
                    a.href = threatPageUrl;
                    a.target = "_blank";
                    a.textContent = "🔍 Voir les détails des menaces détectées";
                    a.className = 'view-details-link';
                  
                    viewDetailsContainer.appendChild(a);
                  }
                  
            } else {
                statusMessage.textContent = "⏳ Analyse en cours...";
                statusIcon.className = 'fas fa-spinner fa-spin status-icon';
            }
        }
    } catch (error) {
        console.error("Erreur récupération popup :", error);
        statusMessage.textContent = "❌ Erreur d'analyse.";
    }

    whitelistBtn.addEventListener('click', async () => {
        if (!activeTab?.url) return;
        const domain = new URL(activeTab.url).hostname;
        const { userWhitelist } = await chrome.storage.sync.get("userWhitelist");
        const updatedList = Array.isArray(userWhitelist) ? [...new Set([...userWhitelist, domain])] : [domain];
        await chrome.storage.sync.set({ userWhitelist: updatedList });
        chrome.runtime.sendMessage({ type: 'WHITELIST_UPDATED' });
        chrome.tabs.reload(activeTab.id);
    });

    reportBtn.addEventListener('click', () => {
        alert("🛠️ Fonction de signalement à implémenter.");
    });

    optionsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });
});
