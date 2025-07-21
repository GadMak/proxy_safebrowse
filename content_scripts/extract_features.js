// content_scripts/extract_features.js

(async function() {
    // Helpers robustes
    function hasTag(sel) {
        return !!document.querySelector(sel);
    }
    function containsText(sel, text) {
        const els = document.querySelectorAll(sel);
        for (let el of els) {
            if (el.textContent && el.textContent.toLowerCase().includes(text.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    async function isResponsive() {
        try {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), 1500);
            await fetch(window.location.href, { signal: controller.signal, method: "HEAD", cache: "no-store" });
            return 1;
        } catch {
            return 0;
        }
    }

    // Calcul de features (tu peux en ajouter d’autres si ton modèle évolue !)
    const url = window.location.href;
    const domain = location.hostname || '';
    const pageTitle = document.title || '';

    const features = [
        url.length, // 1. URLSimilarityIndex (ici : taille de l’URL)
        1.0,        // 2. CharContinuationRate (à calculer si tu as l’algorithme)
        0.06,       // 3. URLCharProb (idem, à raffiner si tu veux)
        (url.match(/[\!\@\#\$\%\^\&\*\(\)\_\+\=\[\]\{\}\|\;\'\:\"\,\.\<\>\/\?]/g) || []).length / url.length, // 4. SpecialCharRatioInURL
        window.location.protocol === "https:" ? 1 : 0, // 5. IsHTTPS
        hasTag('title') ? 1 : 0, // 6. HasTitle
        // 7. DomainTitleMatchScore (similitude domaine/titre, à calculer si besoin)
        domain && pageTitle && pageTitle.toLowerCase().includes(domain.split('.').slice(-2,-1)[0]) ? 1 : 0,
        // 8. URLTitleMatchScore (similitude URL/titre, basique)
        pageTitle && url.toLowerCase().includes(pageTitle.toLowerCase().split(' ')[0]) ? 1 : 0,
        hasTag('link[rel~="icon"], link[rel~="shortcut icon"]') ? 1 : 0, // 9. HasFavicon
        await isResponsive(), // 10. IsResponsive
        hasTag('meta[name="description"]') ? 1 : 0, // 11. HasDescription
        containsText('body', 'facebook') || containsText('body', 'twitter') ? 1 : 0, // 12. HasSocialNet
        hasTag('button[type="submit"], input[type="submit"]') ? 1 : 0, // 13. HasSubmitButton
        document.querySelectorAll('input[type="hidden"]').length > 0 ? 1 : 0, // 14. HasHiddenFields
        containsText('body', 'copyright') ? 1 : 0 // 15. HasCopyrightInfo
    ];

    // Log de debug (tu peux supprimer après)
    // console.log("[SafeBrowse] Features extraites :", features);

    // Envoi des features, avec gestion de réponse
    chrome.runtime.sendMessage({ action: "featuresExtracted", features }, function(resp) {
        // Facultatif : tu peux faire un log de retour ici
    });
})();