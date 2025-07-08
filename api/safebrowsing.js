// /api/safebrowsing.js
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Méthode non autorisée" });
  }

  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL manquante" });
  }

  // Ici tu pourrais ajouter un appel à Google Safe Browsing
  // Pour l’instant, réponse simple :
  if (url.includes("phishing")) {
    return res.json({ safe: false, reason: "URL suspecte" });
  }
  res.json({ safe: true, reason: "URL OK" });
}
