// --- CONSTANTES ET CONFIGURATION ---
const AD_BLOCK_RULES = 4000;
const THREAT_BLOCK_RULES = 1000;
let ADULT_BLOCKLIST = [];
let PHISHING_BLOCKLIST = [];
let currentWhitelist = [];

const SAFE_PROXY_URL = "https://proxysafebrowse.vercel.app/api/check";
const HARDCODED_WHITELIST = [
    "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org"
];

// --- UTILS ---
function normalizeDomain(domain) {
    return domain.replace(/^www\./i, '').toLowerCase();
}

// === Blocage pubs par DNR ===
async function loadAdblockDomainsAndApply() {
    try {
        const url = chrome.runtime.getURL('assets/adblock_list.txt');
        const response = await fetch(url);
        const text = await response.text();
        const domains = text
            .split('\n')
            .map(d => d.trim().replace(/^www\./i, '').toLowerCase())
            .filter(d => d.length > 0 && !d.startsWith('#'))
            .slice(0, AD_BLOCK_RULES);

        const rules = domains.map((domain, idx) => ({
            id: idx + 1,
            priority: 1,
            action: { type: "block" },
            condition: {
                urlFilter: `*://${domain}/*`,
                resourceTypes: [
                    "main_frame", "sub_frame", "script", "xmlhttprequest",
                    "media", "object", "font", "other"
                ]
            }
        }));

        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: Array.from({ length: AD_BLOCK_RULES }, (_, i) => i + 1),
            addRules: rules
        });

        console.log(`[ADBLOCK] ${rules.length} règles de blocage pubs chargées.`);
    } catch (err) {
        console.error("[ADBLOCK] Erreur de chargement/adblock DNR :", err);
    }
}

// === Blocage adultes/phishing par DNR ===
async function applyDynamicThreatBlockingRules() {
    try {
        // Nettoie les anciennes règles 5001-6000
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: Array.from({ length: THREAT_BLOCK_RULES }, (_, i) => i + 5001)
        });

        let rules = [];
        let ruleId = 5001;
        const combinedList = [...ADULT_BLOCKLIST, ...PHISHING_BLOCKLIST];
        const uniqueDomains = Array.from(new Set(combinedList)).slice(0, THREAT_BLOCK_RULES);

        for (const domain of uniqueDomains) {
            rules.push({
                id: ruleId++,
                priority: 1,
                action: { type: "block" },
                condition: {
                    urlFilter: `*://${domain}/*`,
                    resourceTypes: ["main_frame"]
                }
            });
        }

        if (rules.length > 0) {
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: rules });
        }
        console.log(`[DNR] ${rules.length} règles adultes/phishing appliquées.`);
    } catch (error) {
        console.error("[DNR] Erreur lors de l'application des règles dynamiques :", error);
    }
}

// --- Blocklists ---
async function loadBlocklist(file, target) {
    try {
        const url = chrome.runtime.getURL(file);
        const response = await fetch(url);
        const text = await response.text();
        const lines = text.split('\n')
            .map(line => line.trim().replace(/^www\./i, '').toLowerCase())
            .filter(line => line && !line.startsWith('#'));
        console.log(`[DEBUG] Chargement ${target} blocklist :`, lines.slice(0, 5), `... (${lines.length} au total)`);
        return lines;
    } catch (err) {
        console.error(`[SafeBrowse AI] Erreur chargement ${target} blocklist :`, err);
        return [];
    }
}

async function reloadBlocklists() {
    ADULT_BLOCKLIST = await loadBlocklist('assets/adult_blocklist.txt', 'adult');
    PHISHING_BLOCKLIST = await loadBlocklist('assets/phishing_blocklist.txt', 'phishing');
    console.log("[DEBUG] Blocklists rechargées.", { ADULT_BLOCKLIST, PHISHING_BLOCKLIST });
    await applyDynamicThreatBlockingRules();
}

// --- Initialisation ---
chrome.runtime.onInstalled.addListener(async () => {
    await reloadBlocklists();
    await chrome.storage.local.set({
        userWhitelist: [],
        localBlacklist: ["phishing-example.com", "malicious-site.net"]
    });
    await loadAdblockDomainsAndApply();
    chrome.alarms.create('updateBlocklistAlarm', { delayInMinutes: 5, periodInMinutes: 1440 });
});
chrome.runtime.onStartup.addListener(async () => {
    await loadAdblockDomainsAndApply();
    await reloadBlocklists();
});
chrome.alarms.onAlarm.addListener(async alarm => {
    if (alarm.name === 'updateBlocklistAlarm') {
        await reloadBlocklists();
        await loadAdblockDomainsAndApply();
    }
});

// --- Whitelist user ---
chrome.storage.sync.get('userWhitelist', (data) => {
    currentWhitelist = (data.userWhitelist || []).map(normalizeDomain);
});
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync' && changes.userWhitelist) {
        currentWhitelist = (changes.userWhitelist.newValue || []).map(normalizeDomain);
    }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "adsCount") {
        chrome.storage.local.set({ adsBlocked: msg.value });
    }
});

// --- Analyse déclenchée à chaque navigation ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Recharge blocklists si vide (sécurité pour le premier lancement)
        if (!PHISHING_BLOCKLIST.length || !ADULT_BLOCKLIST.length) {
            await reloadBlocklists();
        }
        await analyzeUrlAI(tabId, tab.url);
    }
});

// --- Analyse combinée (listes, heuristique, ML) ---
async function analyzeUrlAI(tabId, url) {
    let domain;
    try { domain = normalizeDomain(new URL(url).hostname); } catch (e) { return; }

    let threats = [];
    let status = 'safe';
    let reason = '';

    console.log(`[DEBUG][analyzeUrlAI] URL: ${url}, domaine: ${domain}`);

    // Moteurs de recherche : jamais bloqués
    if (HARDCODED_WHITELIST.includes(domain)) {
        status = 'safe'; reason = "Moteur de recherche protégé";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await updateUi(tabId, status, domain);
        return;
    }
    // Whitelist utilisateur
    if (currentWhitelist.includes(domain)) {
        status = 'whitelisted'; reason = "Domaine dans la whitelist utilisateur";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await updateUi(tabId, status, domain);
        return;
    }

    // --- Whitelist temporaire "Continuer quand même" ---
    const tempWhitelist = (await chrome.storage.session.get('tempWhitelist')).tempWhitelist || [];
    if (tempWhitelist.includes(domain)) {
        console.log("[DEBUG] Domaine dans la whitelist temporaire, accès autorisé :", domain);
        await setAnalysisStatus(tabId, 'whitelisted', url, domain, [], 'Autorisé temporairement');
        await updateUi(tabId, 'whitelisted', domain);
        return;
    }


    // Blocage immédiat sur blocklist phishing
    if (checkLocalPhishingBlocklist(url)) {
        threats.push("phishing");
        status = "dangerous";
        reason = "Phishing détecté (blocklist locale)";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await blockPage(tabId, domain, reason, url, "phishing"); // <--- Ajouté "phishing"
        return;
    }
    // Blocage immédiat sur blocklist adulte
    if (checkLocalAdultBlocklist(url)) {
        threats.push("adult");
        status = "dangerous";
        reason = "Site adulte détecté (blocklist locale)";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await blockPage(tabId, domain, reason, url, "adult"); // <--- Ajouté "adult"
        return;
    }

    // Option désactivée ?
    const { enableThreats = true } = await chrome.storage.sync.get("enableThreats");
    if (!enableThreats) {
        status = 'safe'; reason = "Analyse désactivée";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await updateUi(tabId, status, domain);
        return;
    }

    // Google Safe Browsing (proxy)
    if (await checkGoogleSafeBrowseProxy(url)) {
        threats.push("phishing");
        status = "dangerous";
        reason = "Phishing détecté (Google Safe Browsing)";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await blockPage(tabId, domain, reason, url, "phishing"); // <--- Ajouté "phishing"
        return;
    }

    // Heuristique
    if (checkHeuristic(url)) {
        threats.push("threat", "heuristic");
        status = "dangerous";
        reason = "Contenu suspect détecté (heuristique)";
        await setAnalysisStatus(tabId, status, url, domain, threats, reason);
        await updateUi(tabId, status, domain);
        return;
    }

    // ML/IA (optionnel, ne bloque jamais si planté)
    const features = await extractFeaturesWithContentScript(tabId);
    if (features && Array.isArray(features) && features.length > 0) {
        const mlResult = await checkPhishingWithML(features);
        if (mlResult.is_phishing) {
            threats.push("phishing");
            status = "dangerous";
            reason = "Phishing détecté (IA ML)";
            await setAnalysisStatus(tabId, status, url, domain, threats, reason);
            await blockPage(tabId, domain, reason, url, "phishing"); // <--- Ajouté "phishing"
            return;
        }
        if (mlResult.has_vuln) {
            threats.push("vulnerability");
        }
        if (mlResult.ads && mlResult.ads > 0) {
            threats.push("ads");
        }
    }

    // Statut global
    if (threats.length > 0 && status !== 'dangerous') {
        status = 'dangerous';
        if (!reason) reason = "Menaces détectées (non phishing)";
    }
    await setAnalysisStatus(tabId, status, url, domain, threats, reason);
    await updateUi(tabId, status, domain);
}

// --- Extraction des features depuis le content script ---
async function extractFeaturesWithContentScript(tabId) {
    return new Promise((resolve) => {
        chrome.scripting.executeScript({
            target: { tabId },
            files: ['content_scripts/extract_features.js']
        }, () => {
            const listener = (message, sender) => {
                if (sender.tab && sender.tab.id === tabId && message.action === "featuresExtracted") {
                    chrome.runtime.onMessage.removeListener(listener);
                    resolve(message.features);
                }
            };
            chrome.runtime.onMessage.addListener(listener);
        });
    });
}

// --- Appel API ML ---
async function checkPhishingWithML(features) {
    try {
        const response = await fetch("https://web-production-30897.up.railway.app/predict", {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features })
        });
        const data = await response.json();
        return data;
    } catch (e) {
        // ==> Ne bloque JAMAIS si l’API ML tombe
        return { is_phishing: false, has_vuln: false, ads: 0 };
    }
}

async function setAnalysisStatus(tabId, status, url, domain, threats = [], reason = "") {
    if (!tabId || isNaN(tabId)) {
        console.warn("setAnalysisStatus: tabId indéfini !", tabId);
        return;
    }
    const obj = {
        status,
        url,
        domain,
        threats,
        reason,
        analysisTime: Date.now()
    };
    await chrome.storage.local.set({ [`threats_${tabId}`]: obj });
}

async function clearThreat(tabId) {
    await chrome.storage.local.remove([`threats_${tabId}`]);
}

async function blockPage(tabId, domain, reason, url = null, threatType = "phishing") {
    let page = "phish_block.html";
    if (threatType === "adult") {
        page = "blocking_page.html";
    } else if (threatType === "phishing") {
        page = "phish_block.html";
    } else {
        page = "blocking_page.html";
    }
    if (url) {
        chrome.tabs.get(tabId, async (tab) => {
            // On garde la logique basique pour que le blocage refonctionne
            if (tab && tab.url && tab.url.startsWith("http")) {
                await chrome.storage.local.set({ [`lastUrl_${tabId}`]: tab.url });
            }
            // Redirige SANS sessions.getTabValue/setTabValue qui peut bloquer la suite !
            await chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL(`pages/${page}?site=${encodeURIComponent(domain)}&reason=${encodeURIComponent(reason)}&tabId=${tabId}`)
            });
        });
    } else {
        await chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL(`pages/${page}?site=${encodeURIComponent(domain)}&reason=${encodeURIComponent(reason)}`)
        });
    }
}

async function updateUi(tabId, status, domain) {
    try {
        const iconPath = ICON_PATHS[status] || ICON_PATHS.default;
        await chrome.action.setIcon({ tabId, path: iconPath });
    } catch (error) {
        if (!error.message.includes("No tab with id")) {
            console.error(`[SafeBrowse AI] Erreur update UI onglet ${tabId} :`, error);
        }
    }
}

function checkLocalPhishingBlocklist(url) {
    if (!PHISHING_BLOCKLIST.length) return false;
    const { hostname } = new URL(url);
    const normDomain = normalizeDomain(hostname);
    const found = PHISHING_BLOCKLIST.some(entry => {
        const normEntry = normalizeDomain(entry);
        return normDomain === normEntry || normDomain.endsWith('.' + normEntry);
    });
    console.log("[DEBUG] PHISHING_BLOCKLIST", PHISHING_BLOCKLIST, "Testé :", normDomain, "Résultat:", found);
    return found;
}

function checkLocalAdultBlocklist(url) {
    if (!ADULT_BLOCKLIST.length) return false;
    const { hostname } = new URL(url);
    const normDomain = normalizeDomain(hostname);
    const found = ADULT_BLOCKLIST.some(entry => {
        const normEntry = normalizeDomain(entry);
        return normDomain === normEntry || normDomain.endsWith('.' + normEntry);
    });
    console.log("[DEBUG] ADULT_BLOCKLIST", ADULT_BLOCKLIST, "Testé :", normDomain, "Résultat:", found);
    return found;
}

function checkHeuristic(url) {
    const patterns = [
        /login.*secure/i,
        /update.*paypal/i,
        /verify.*account/i,
        /bank.*verify/i,
        /gift.*free/i,
        /confirm.*identity/i,
        /\.ru\//i,
        /xn--/, /@.*@/,
        /(\.zip|\.rar)\/?$/i
    ];
    return patterns.some(re => re.test(url));
}

// --- (déclarativeNetRequest pas modifié ici) ---

async function checkGoogleSafeBrowseProxy(url) {
    try {
        const response = await fetch(SAFE_PROXY_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        return data.matches && data.matches.length > 0;
    } catch (error) {
        console.error("[SafeBrowse AI] Erreur proxy Safe Browsing :", error);
        return false;
    }
}