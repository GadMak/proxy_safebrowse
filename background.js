// --- CONSTANTES ET CONFIGURATION ---
const ICON_PATHS = {
    safe: { "16": "images/icon_safe_16.png", "32": "images/icon_safe_32.png" },
    dangerous: { "16": "images/icon_danger_16.png", "32": "images/icon_danger_32.png" },
    warning: { "16": "images/icon_warning_16.png", "32": "images/icon_warning_32.png" },
    whitelisted: { "16": "images/icon_whitelisted_16.png", "32": "images/icon_whitelisted_16.png" },
    default: { "16": "images/icon16.png", "32": "images/icon32.png" }
};
const MAX_DYNAMIC_RULES = 5000;
let ADULT_BLOCKLIST = []; // Chargée dynamiquement
let PHISHING_BLOCKLIST = []; // Blocklist phishing locale
let currentWhitelist = [];

// URL proxy Google Safe Browsing
const SAFE_PROXY_URL = "https://proxysafebrowse.vercel.app/api/check";

// --- UTILS ---
function normalizeDomain(domain) {
    return domain.replace(/^www\./i, '').toLowerCase();
}

// --- Chargement de la blocklist adulte ---
async function loadAdultBlocklist() {
    try {
        const url = chrome.runtime.getURL('assets/adult_blocklist.txt');
        const response = await fetch(url);
        const text = await response.text();
        ADULT_BLOCKLIST = text
            .split('\n')
            .map(line => line.trim().replace(/^www\./i, '').toLowerCase())
            .filter(line => line && !line.startsWith('#'));
        console.log(`[SafeBrowse AI] Blocklist adultes chargée : ${ADULT_BLOCKLIST.length} domaines.`);
    } catch (err) {
        console.error('[SafeBrowse AI] Erreur chargement blocklist adulte :', err);
        ADULT_BLOCKLIST = [];
    }
}

// --- Chargement de la blocklist phishing locale ---
async function loadPhishingBlocklist() {
    try {
        const url = chrome.runtime.getURL('assets/phishing_blocklist.txt');
        const response = await fetch(url);
        const text = await response.text();
        PHISHING_BLOCKLIST = text
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'));
        console.log(`[SafeBrowse AI] Blocklist phishing chargée : ${PHISHING_BLOCKLIST.length} URLs.`);
    } catch (err) {
        console.error('[SafeBrowse AI] Erreur chargement blocklist phishing :', err);
        PHISHING_BLOCKLIST = [];
    }
}

// --- (Re)charge les blocklists à chaque démarrage ---
loadAdultBlocklist();
loadPhishingBlocklist();

// --- Événements d'installation et d'update ---
chrome.runtime.onInstalled.addListener(async () => {
    await loadAdultBlocklist();
    await loadPhishingBlocklist();
    await chrome.storage.local.set({
        userWhitelist: [],
        localBlacklist: ["phishing-example.com", "malicious-site.net"]
    });
    await fetchAndUpdateRules();
    chrome.alarms.create('updateBlocklistAlarm', { delayInMinutes: 5, periodInMinutes: 1440 });
});

chrome.alarms.onAlarm.addListener(async alarm => {
    if (alarm.name === 'updateBlocklistAlarm') {
        await loadAdultBlocklist();
        await loadPhishingBlocklist();
        await fetchAndUpdateRules();
    }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync' && changes.userWhitelist) {
        currentWhitelist = (changes.userWhitelist.newValue || []).map(normalizeDomain);
    }
});

chrome.storage.sync.get('userWhitelist', (data) => {
    currentWhitelist = (data.userWhitelist || []).map(normalizeDomain);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        if (!tab.url.startsWith(chrome.runtime.getURL(''))) {
            chrome.storage.sync.get({ enablePhishing: true }, (settings) => {
                if (settings.enablePhishing) {
                    analyzeUrlWithSafeProxy(tabId, tab.url);
                }
            });
        }
    }
});

// --- Gestion des messages/threats ---
chrome.runtime.onMessage.addListener(async (message, sender) => {
    const tabId = sender.tab?.id;
    const url = message.url;
    if (!tabId || !url) return;

    if (message.action === 'threatDetected') {
        await chrome.storage.local.set({
            [`threats_${tabId}`]: {
                status: 'warning',
                url,
                threats: message.threats
            }
        });
        await chrome.action.setIcon({ tabId, path: ICON_PATHS.warning });
    }

    if (message.action === 'noThreatDetected') {
        await chrome.storage.local.set({
            [`threats_${tabId}`]: {
                status: 'safe',
                url,
                threats: []
            }
        });
        await chrome.action.setIcon({ tabId, path: ICON_PATHS.safe });
    }
});

// --- Vérifie si l'URL figure dans la blocklist phishing locale ---
function checkLocalPhishingBlocklist(url) {
    if (!PHISHING_BLOCKLIST.length) return false;
    // Vérifie si l'URL commence par une URL de la liste
    return PHISHING_BLOCKLIST.some(phishUrl => url.startsWith(phishUrl));
}

// --- Analyse heuristique simple ---
function checkHeuristic(url) {
    const patterns = [
        /login.*secure/i,
        /update.*paypal/i,
        /verify.*account/i,
        /bank.*verify/i,
        /gift.*free/i,
        /confirm.*identity/i,
        /\.ru\//i,
        /xn--/, // Punycode
        /@.*@/, // Plusieurs @ dans l'URL
        /(\.zip|\.rar)\/?$/i
    ];
    return patterns.some(re => re.test(url));
}

// --- Obtenir la liste des domaines à bloquer (adulte + blacklist locale) ---
async function getBlocklistDomains() {
    const settings = await chrome.storage.sync.get({
        userWhitelist: [],
        localBlacklist: [],
        enableAdultBlocking: true
    });
    return [
        ...new Set([
            ...(ADULT_BLOCKLIST || []),
            ...(settings.localBlacklist || [])
        ])
    ];
}

// --- Génération des règles dynamiques ---
async function generateDeclarativeNetRequestRules() {
    const settings = await chrome.storage.sync.get({
        userWhitelist: [],
        localBlacklist: [],
        enableAdultBlocking: true
    });
    const userWhitelist = (settings.userWhitelist || []).map(normalizeDomain);
    let domainsToBlock = await getBlocklistDomains();

    domainsToBlock = Array.from(new Set(domainsToBlock.map(normalizeDomain)))
        .filter(d => !userWhitelist.includes(d))
        .slice(0, MAX_DYNAMIC_RULES);

    if (domainsToBlock.length === MAX_DYNAMIC_RULES) {
        console.warn(`[SafeBrowse AI] La blocklist adulte a été TRONQUÉE à ${MAX_DYNAMIC_RULES} domaines (limite Chrome) !`);
    }

    const rulesToAdd = [];
    let ruleIdCounter = 1;

    for (const domain of domainsToBlock) {
        rulesToAdd.push({
            id: ruleIdCounter++,
            priority: 1,
            action: {
                type: "redirect",
                redirect: {
                    url: chrome.runtime.getURL(`pages/blocking_page.html?site=${encodeURIComponent(domain)}`)
                }
            },
            condition: {
                urlFilter: `||${domain}^`,
                resourceTypes: ["main_frame"]
            }
        });
    }

    try {
        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingRules.map(rule => rule.id),
            addRules: rulesToAdd
        });
        console.log(`[SafeBrowse AI] ${rulesToAdd.length} règles dynamiques actives.`);
    } catch (error) {
        console.error("[SafeBrowse AI] Erreur de mise à jour des règles dynamiques :", error);
    }
}

async function fetchAndUpdateRules() {
    const { enableAdultBlocking = true } = await chrome.storage.sync.get("enableAdultBlocking");
    if (!enableAdultBlocking) return;
    await generateDeclarativeNetRequestRules();
}

// --- Chaîne de détection Phishing (proxy + local + heuristique) ---
async function analyzeUrlWithSafeProxy(tabId, url) {
    let domain;
    try {
        domain = normalizeDomain(new URL(url).hostname);
    } catch (e) {
        return;
    }
    if (currentWhitelist.includes(domain)) {
        await updateUi(tabId, 'whitelisted', domain);
        return;
    }
    const { enableThreats = true } = await chrome.storage.sync.get("enableThreats");
    if (!enableThreats) return;

    // 1. Google Safe Browsing Proxy
    const isDangerousGSB = await checkGoogleSafeBrowseProxy(url);
    if (isDangerousGSB) {
        await blockPage(tabId, domain, 'Phishing détecté (Google Safe Browsing)');
        return;
    }

    // 2. Blocklist locale phishing
    const isDangerousPhishBlocklist = checkLocalPhishingBlocklist(url);
    if (isDangerousPhishBlocklist) {
        await blockPage(tabId, domain, 'Phishing détecté (blocklist locale)');
        return;
    }

    // 3. Heuristique
    const isDangerousHeur = checkHeuristic(url);
    if (isDangerousHeur) {
        await blockPage(tabId, domain, 'Phishing détecté (Analyse heuristique)');
        return;
    }

    // Aucun danger détecté
    await updateUi(tabId, 'safe', domain);
}

async function blockPage(tabId, domain, reason) {
    await updateUi(tabId, 'dangerous', domain);
    const blockingUrl = chrome.runtime.getURL(`pages/blocking_page.html?site=${encodeURIComponent(domain)}&reason=${encodeURIComponent(reason)}`);
    chrome.tabs.update(tabId, { url: blockingUrl });
}

async function updateUi(tabId, status, domain) {
    try {
        await chrome.storage.local.set({ [`threats_${tabId}`]: { status, domain } });
        const iconPath = ICON_PATHS[status] || ICON_PATHS.default;
        await chrome.action.setIcon({ tabId: tabId, path: iconPath });
    } catch (error) {
        if (!error.message.includes("No tab with id")) {
            console.error(`[SafeBrowse AI] Erreur update UI onglet ${tabId} :`, error);
        }
    }
}

// --- Fonction pour communiquer avec le proxy Google Safe Browsing ---
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
        console.error("[SafeBrowse AI] Erreur communication proxy Safe Browsing :", error);
        return false;
    }
}