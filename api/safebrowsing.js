export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Méthode non autorisée" });
  }

  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL manquante" });
  }

  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  const googleUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: {
      clientId: "SafeBrowse-AI-Extension",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await fetch(googleUrl, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" }
    });
    const data = await response.json();

    if (data && data.matches && data.matches.length > 0) {
      return res.status(200).json({
        safe: false,
        reason: "Phishing/malware détecté par Google"
      });
    } else {
      return res.status(200).json({
        safe: true,
        reason: "Aucune menace détectée"
      });
    }
  } catch (error) {
    return res.status(500).json({ error: "Erreur lors de la vérification Google Safe Browsing" });
  }
}
