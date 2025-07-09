document.addEventListener("DOMContentLoaded", () => {
    const container = document.getElementById("threatListContainer");
    const backLink = document.getElementById("backLink");
  
    // 1. Récupérer les paramètres d’URL
    const params = new URLSearchParams(window.location.search);
    const encodedData = params.get("data");
    const encodedSource = params.get("source");
  
    // 2. Bouton retour vers l’URL d’origine
    if (encodedSource) {
      const decodedSource = decodeURIComponent(encodedSource);
      backLink.href = decodedSource;
    } else {
      backLink.href = "../popup/popup.html";
    }
  
    // 3. Afficher les menaces
    if (encodedData) {
      try {
        const decoded = atob(decodeURIComponent(encodedData));
        const threats = JSON.parse(decoded);
  
        if (Array.isArray(threats) && threats.length > 0) {
          threats.forEach((desc) => {
            const div = document.createElement("div");
            div.className = "threat-item";
            div.innerHTML = `
              <i class="fas fa-exclamation-circle"></i>
              <div class="threat-desc">${desc}</div>`;
            container.appendChild(div);
          });
          return;
        }
      } catch (e) {
        console.error("Erreur de décodage des menaces :", e);
      }
    }
  
    // 4. Aucune menace trouvée
    container.innerHTML = `
      <div class="no-threats">
        <i class='fas fa-shield-alt'></i> Aucune menace détectée sur cette page.
      </div>`;
  });  
