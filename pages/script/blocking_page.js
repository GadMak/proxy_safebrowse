// js/blocking_page.js

document.addEventListener('DOMContentLoaded', () => {
    const blockedUrlDisplay = document.getElementById('blockedUrlDisplay');
    const reasonMessage = document.getElementById('reasonMessage');
    const goBackBtn = document.getElementById('goBackBtn');
    const reportFalsePositiveBtn = document.getElementById('reportFalsePositiveBtn');
    const proceedAnywayBtn = document.getElementById('proceedAnywayBtn');

    // --- Lire les paramètres de l'URL ---
    const urlParams = new URLSearchParams(window.location.search);
    const blockedSite = urlParams.get('site') || 'URL inconnue';
    const reason = urlParams.get('reason') || 'unknown';

    // --- Afficher l'URL bloquée ---
    blockedUrlDisplay.textContent = blockedSite;

    // --- Déterminer la raison ---
    const reasonMap = {
        'local_blacklist': 'Ce site a été identifié dans notre liste noire locale.',
        'google_safe_Browse': 'Ce site a été signalé comme dangereux par Google Safe Browsing.',
        'heuristic_threat': 'Des menaces potentielles ont été détectées par l\'analyse heuristique.',
        'adult_content': 'Ce site contient du contenu réservé aux adultes.',
        'unknown': 'Ce site présente des caractéristiques de menace.'
    };

    reasonMessage.textContent = `Raison : ${reasonMap[reason] || reasonMap['unknown']}`;

    // --- Bouton : Retour arrière ---
    goBackBtn.addEventListener('click', () => {
        window.history.back();
    });

    // --- Bouton : Signaler faux positif ---
    reportFalsePositiveBtn.addEventListener('click', () => {
        const reportUrl = `https://forms.gle/YOUR_FORM_LINK?url=${encodeURIComponent(blockedSite)}&reason=${encodeURIComponent(reason)}`;
        alert(`Merci de signaler ce faux positif. La page de signalement va s’ouvrir pour : ${blockedSite}`);
        chrome.tabs.create({ url: reportUrl });
    });

    // --- Bouton : Continuer quand même ---
    proceedAnywayBtn.addEventListener('click', async () => {
        const confirmProceed = confirm(
            `⚠️ Voulez-vous vraiment continuer vers "${blockedSite}" ?\n` +
            `Ce site a été bloqué car il pourrait être dangereux.`
        );

        if (!confirmProceed) return;

        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            const currentTabId = tabs[0]?.id;
            if (!currentTabId) throw new Error("Aucun onglet actif trouvé.");

            // Envoi au background pour autorisation temporaire
            chrome.runtime.sendMessage({
                action: 'allowTemporaryAccess',
                url: blockedSite,
                tabId: currentTabId
            }, (response) => {
                if (chrome.runtime.lastError) {
                    alert("Erreur de communication avec l'extension.");
                    return;
                }

                if (response && response.status === 'success') {
                    chrome.tabs.update(currentTabId, { url: `https://${blockedSite}` });
                    window.close();
                } else {
                    alert("Impossible d'accéder au site. Une erreur est survenue.");
                }
            });

        } catch (err) {
            console.error("[SafeBrowse AI] Erreur lors de la tentative de poursuite :", err);
            alert("Impossible d’ouvrir ce site.");
        }
    });
});
