// Sélecteurs ultra-ciblés (enrichis)
const AD_SELECTORS = [
    'iframe[src*="ads"]',
    'iframe[src*="advert"]',
    'iframe[src*="doubleclick"]',
    'iframe[src*="adservice"]',
    'iframe[src*="syndication"]',
    'iframe[src*="zedo"]',
    'iframe[src*="mgid"]',
    'iframe[src*="taboola"]',
    'iframe[src*="outbrain"]',
    'iframe[src*="propellerads"]',
    'iframe[src*="adsterra"]',
    '.adsbygoogle',
    '.ad-container',
    '.ad-banner',
    '.advertisement',
    '.sponsored',
    '.sponsor',
    '.ad-slot',
    '.ad-slot-container',
    'div[data-ad]',
    'div[data-testid="ad"]',
    'ins.adsbygoogle',
    // Popups/overlay
    'div[class*="modal"]',
    'div[class*="popup"]',
    'div[id*="modal"]',
    'div[id*="popup"]',
    '.overlay',
    '.modal',
    '.popup',
    '.lightbox',
    // Spécifiques
    'div[class*="newsblock"]',
    'div[class*="adsense"]',
    'div[class*="sponsored"]'
  ];
  
  // Sélecteurs à ne pas masquer (UI critique), personnalise si besoin
  const UI_WHITELIST = [
    // 'button.ad-button', '[id="advantage"]'
  ];
  
  // Heuristique : détecte les pubs par texte ou contenu
  function isFakeAd(element) {
    const texts = [
      "reçu", "appuyez pour recevoir", "continuer", "maillot de bain",
      "bikini", "remporter", "gagnant", "argent", "cliquez ici", "fermer", "publicité"
    ];
    if (!element.textContent) return false;
    const txt = element.textContent.toLowerCase();
    return texts.some(t => txt.includes(t));
  }
  
  // Filtre principal
  function hideAdsSmartly() {
    // 1. Cible les sélecteurs connus et les cache
    AD_SELECTORS.forEach(selector => {
      document.querySelectorAll(selector).forEach(el => {
        // Exclusion UI critique
        if (UI_WHITELIST.some(w => el.matches(w))) return;
        el.style.display = 'none';
        el.style.visibility = 'hidden';
        el.style.minHeight = '0';
        el.style.maxHeight = '0';
        el.style.height = '0';
        el.style.width = '0';
        el.style.pointerEvents = 'none';
        el.style.opacity = '0';
      });
    });
  
    // 2. Heuristique : div fixes, z-index élevé + texte suspect (pour les popups)
    document.querySelectorAll('div[style*="z-index"]').forEach(el => {
      const style = window.getComputedStyle(el);
      if (
        (style.position === 'fixed' || style.position === 'absolute') &&
        (parseInt(style.zIndex, 10) > 900 || style.zIndex === 'auto') &&
        isFakeAd(el)
      ) {
        el.style.display = 'none';
        el.style.visibility = 'hidden';
        el.style.pointerEvents = 'none';
        el.style.opacity = '0';
      }
    });
  
    // 3. Supprime les iframes suspectes (taille et src)
    document.querySelectorAll('iframe').forEach(iframe => {
      try {
        const src = iframe.src || '';
        if (
          src.match(/(ads|advert|popunder|doubleclick|syndication|adservice|zedo|mgid|popads|taboola|outbrain|propellerads|adsterra)/i)
          || (iframe.width >= 300 && iframe.height >= 250)
        ) {
          iframe.remove();
        }
      } catch (e) { /* cross-origin, on ignore */ }
    });
  }
  
  // Lance la détection dès le chargement
  hideAdsSmartly();
  
  // Relance la détection sur toute mutation du DOM (pubs dynamiques)
  const observer = new MutationObserver(() => {
    hideAdsSmartly();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  function hideInShadowDOM(root = document) {
    // Recursion pour tous les nodes
    (root.querySelectorAll('*') || []).forEach(node => {
      if (node.shadowRoot) {
        // Remasque tout selon AD_SELECTORS dans ce shadowRoot
        AD_SELECTORS.forEach(selector => {
          node.shadowRoot.querySelectorAll(selector).forEach(el => {
            el.style.display = 'none';
            el.style.visibility = 'hidden';
            el.style.opacity = '0';
          });
        });
        hideInShadowDOM(node.shadowRoot);
      }
    });
  }
  hideInShadowDOM();
  