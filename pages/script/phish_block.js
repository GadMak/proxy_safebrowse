// js/phish_block.js

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
    if (goBackBtn) {
        goBackBtn.addEventListener('click', () => {
            if (window.history.length > 2) {
                window.history.go(-2); // Double retour
            } else if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = "https://www.google.com/";
            }
        });
    }    
    

    // --- Bouton : Signaler faux positif ---
    reportFalsePositiveBtn.addEventListener('click', () => {
        const reportUrl = `https://forms.gle/YOUR_FORM_LINK?url=${encodeURIComponent(blockedSite)}&reason=${encodeURIComponent(reason)}`;
        alert(`Merci de signaler ce faux positif. La page de signalement va s’ouvrir pour : ${blockedSite}`);
        chrome.tabs.create({ url: reportUrl });
    });

// --- Bouton : Continuer quand même ---
proceedAnywayBtn.addEventListener('click', () => {
    const confirmProceed = confirm(
        `⚠️ Voulez-vous vraiment continuer vers "${blockedSite}" ?\n` +
        `Ce site a été bloqué car il pourrait être dangereux.`
    );

    if (!confirmProceed) return;

    chrome.storage.session.get(['tempWhitelist'], (data) => {
        let tempWhitelist = data.tempWhitelist || [];
        if (!tempWhitelist.includes(blockedSite)) {
            tempWhitelist.push(blockedSite);
            chrome.storage.session.set({ tempWhitelist }, () => {
                window.location.href = "https://" + blockedSite;
            });
        } else {
            window.location.href = "https://" + blockedSite;
        }
    });
});

});