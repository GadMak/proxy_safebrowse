// js/options.js

document.addEventListener('DOMContentLoaded', async () => {
    // Interrupteurs de sécurité
    const enablePhishingDetection = document.getElementById('enablePhishingDetection');
    const enableThreatDetection = document.getElementById('enableThreatDetection');
    const enableVulnerabilityDetection = document.getElementById('enableVulnerabilityDetection');
    const enableAdultBlocking = document.getElementById('enableAdultBlocking');
    const enableAdBlocking = document.getElementById('enableAdBlocking');

    // Liste blanche
    const whitelistInput = document.getElementById('whitelistInput');
    const addWhitelistBtn = document.getElementById('addWhitelistBtn');
    const whitelistList = document.getElementById('whitelistList');

    // Enregistrement
    const saveOptionsBtn = document.getElementById('saveOptionsBtn');
    const statusMessageDiv = document.getElementById('statusMessage');

    // Afficher un message temporaire
    const showStatusMessage = (message, type) => {
        statusMessageDiv.textContent = message;
        statusMessageDiv.className = `status-message ${type} visible`;
        setTimeout(() => {
            statusMessageDiv.classList.remove('visible');
            statusMessageDiv.textContent = '';
        }, 3000);
    };

    const normalizeDomain = (domain) => {
        return domain.replace(/^www\./, '').toLowerCase();
    };

    // Charger les options sauvegardées
    const loadOptions = async () => {
        try {
            const options = await chrome.storage.sync.get({
                enablePhishing: true,
                enableThreats: true,
                enableVulnerabilities: true,
                enableAdultBlocking: true,
                enableAdBlocking: true,
                userWhitelist: []
            });

            enablePhishingDetection.checked = options.enablePhishing;
            enableThreatDetection.checked = options.enableThreats;
            enableVulnerabilityDetection.checked = options.enableVulnerabilities;
            enableAdultBlocking.checked = options.enableAdultBlocking;
            enableAdBlocking.checked = options.enableAdBlocking;

            renderWhitelist(Array.isArray(options.userWhitelist) ? options.userWhitelist : []);
            console.log("SafeBrowse AI - Options chargées :", options);
        } catch (err) {
            console.error("Erreur lors du chargement des options :", err);
        }
    };

    // Sauvegarder les options
    const saveOptions = async () => {
        try {
            const options = {
                enablePhishing: enablePhishingDetection.checked,
                enableThreats: enableThreatDetection.checked,
                enableVulnerabilities: enableVulnerabilityDetection.checked,
                enableAdultBlocking: enableAdultBlocking.checked,
                enableAdBlocking: enableAdBlocking.checked
            };

            await chrome.storage.sync.set(options);
            showStatusMessage('Paramètres enregistrés avec succès !', 'success');
            console.log("SafeBrowse AI - Options sauvegardées :", options);
        } catch (err) {
            console.error("Erreur lors de la sauvegarde :", err);
            showStatusMessage('Erreur lors de la sauvegarde.', 'error');
        }
    };

    // Afficher la liste blanche
    const renderWhitelist = (whitelist) => {
        whitelistList.innerHTML = '';
        if (!whitelist || whitelist.length === 0) {
            const li = document.createElement('li');
            li.textContent = "Aucun site sur liste blanche.";
            li.style.color = '#777';
            whitelistList.appendChild(li);
            return;
        }

        whitelist.forEach(domain => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span>${domain}</span>
                <button class="remove-btn" data-domain="${domain}">
                    <i class="fas fa-times-circle"></i>
                </button>
            `;
            whitelistList.appendChild(li);
        });

        // Ajouter les événements sur les boutons de suppression
        document.querySelectorAll('.remove-btn').forEach(button => {
            button.addEventListener('click', removeDomainFromWhitelist);
        });
    };

    // Ajouter un domaine à la liste blanche
    const addDomainToWhitelist = async () => {
        const rawDomain = whitelistInput.value.trim().toLowerCase();
        const domain = normalizeDomain(rawDomain);

        if (!domain) {
            return showStatusMessage('Veuillez entrer un domaine valide.', 'error');
        }

        if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
            return showStatusMessage('Format de domaine invalide (ex: example.com).', 'error');
        }

        const { userWhitelist } = await chrome.storage.sync.get("userWhitelist");
        const currentList = Array.isArray(userWhitelist) ? [...userWhitelist] : [];

        const normalizedList = currentList.map(normalizeDomain);
        if (normalizedList.includes(domain)) {
            return showStatusMessage('Ce domaine est déjà dans la liste blanche.', 'warning');
        }

        const updatedList = [...new Set([...currentList, domain])].sort();

        await chrome.storage.sync.set({ userWhitelist: updatedList });
        renderWhitelist(updatedList);
        whitelistInput.value = '';
        showStatusMessage('Domaine ajouté à la liste blanche.', 'success');

        chrome.runtime.sendMessage({ type: 'WHITELIST_UPDATED' });
    };

    // Supprimer un domaine
    const removeDomainFromWhitelist = async (event) => {
        const domainToRemove = event.currentTarget.dataset.domain;
        const { userWhitelist } = await chrome.storage.sync.get("userWhitelist");
        const updatedList = (userWhitelist || []).filter(domain => domain !== domainToRemove);

        await chrome.storage.sync.set({ userWhitelist: updatedList });
        renderWhitelist(updatedList);
        showStatusMessage(`"${domainToRemove}" retiré de la liste blanche.`, 'success');

        chrome.runtime.sendMessage({ type: 'WHITELIST_UPDATED' });
    };

    // Initialisation
    await loadOptions();

    saveOptionsBtn.addEventListener('click', saveOptions);
    addWhitelistBtn.addEventListener('click', addDomainToWhitelist);
    whitelistInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') addDomainToWhitelist();
    });

    // Mettre à jour la liste blanche si modifiée depuis un autre onglet
    chrome.storage.sync.onChanged.addListener((changes, areaName) => {
        if (areaName === 'sync' && changes.userWhitelist) {
            renderWhitelist(changes.userWhitelist.newValue);
        }
    });

    console.log("SafeBrowse AI - options.js chargé.");
});
