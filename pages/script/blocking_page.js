document.addEventListener('DOMContentLoaded', () => {
    // --- Récupération des éléments DOM ---
    const blockedUrlDisplay = document.getElementById('blockedUrlDisplay');
    const reasonMessage = document.getElementById('reasonMessage');
    const goBackBtn = document.getElementById('goBackBtn');
    const reportFalsePositiveBtn = document.getElementById('reportFalsePositiveBtn');

    // --- Lire les paramètres de l'URL ---
    const urlParams = new URLSearchParams(window.location.search);
    const blockedSite = urlParams.get('site') || 'URL inconnue';
    const reason = urlParams.get('reason') || 'unknown';
    const tabId = urlParams.get('tabId');  // peut être null

    // --- Afficher l'URL bloquée ---
    if (blockedUrlDisplay) blockedUrlDisplay.textContent = blockedSite;

    // --- Déterminer la raison ---
    const reasonMap = {
        'local_blacklist': 'Ce site a été identifié dans notre liste noire locale.',
        'google_safe_Browse': 'Ce site a été signalé comme dangereux par Google Safe Browsing.',
        'heuristic_threat': 'Des menaces potentielles ont été détectées par l\'analyse heuristique.',
        'adult_content': 'Ce site contient du contenu réservé aux adultes.',
        'phishing': 'Ce site a été détecté comme du phishing.',
        'unknown': 'Ce site présente des caractéristiques de menace.'
    };
    if (reasonMessage) {
        reasonMessage.textContent = `Raison : ${reasonMap[reason] || reasonMap['unknown']}`;
    }

    // --- Bouton : Retour arrière ---
    if (goBackBtn) {
        goBackBtn.addEventListener('click', () => {
            const tabId = urlParams.get('tabId');
            if (tabId) {
                chrome.storage.local.get([`lastUrl_${tabId}`], (data) => {
                    const previousUrl = data[`lastUrl_${tabId}`];
                    if (window.history.length > 2) {
                        window.history.go(-2); // Recule de deux pages
                    } else if (window.history.length > 1) {
                        window.history.back();
                    } else {
                        tryCloseOrRedirect();
                    }                    
                });
            } else {
                window.location.href = "https://www.google.com/";
            }
        });
    }       

    // --- Bouton : Signaler faux positif (version email direct via API/serveur) ---
    if (reportFalsePositiveBtn) {
        reportFalsePositiveBtn.addEventListener('click', () => {
            fetch('https://web-production-30897.up.railway.app/report-false-positive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ site: blockedSite })
            })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    alert('Merci, le signalement a bien été envoyé !');
                } else {
                    alert('Erreur lors de l\'envoi du signalement.');
                }
            })
            .catch(err => {
                alert('Erreur réseau lors de l\'envoi du signalement.');
            });
        });
    }
});