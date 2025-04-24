const axios = require('axios');
require('dotenv').config();

const enrichWithIA = async (input) => {
  // On récupère uniquement les IOCs s’ils existent
  const potentialIOCs = input?.potential_iocs;
  const iocsList = Array.isArray(potentialIOCs) ? potentialIOCs.join('\n') : null;

  const content = iocsList 
    ? `Voici une liste d'indicateurs de compromission extraits d'une analyse de trafic réseau :\n\n${iocsList}\n\nFaites un résumé concis (4-5 lignes) de ce que ces éléments suggèrent sur l'activité du réseau, puis proposez des actions de sécurité à entreprendre.` 
    : `Voici une analyse de fichier PCAP complète : ${JSON.stringify(input)}\n\nFaites un résumé de ce que vous observez et proposez des actions à entreprendre.`;

  try {
    const response = await axios.post(
      `${process.env.MISTRAL_API_URL}/chat/completions`,
      {
        model: "mistral-nemo-instruct-2407",
        messages: [
          { role: "system", content: "Vous êtes un assistant de sécurité informatique et vous analysez des incidents à partir de fichiers de logs ou d'indicateurs de compromission (IOC)." },
          { role: "user", content }
        ],
        max_tokens: 512,
        temperature: 0.4,
        top_p: 1,
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.MISTRAL_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data.choices[0].message.content;
  } catch (error) {
    console.error("❌ Erreur appel Mistral :", error.response?.data || error.message);
    return "Erreur lors de l'analyse IA.";
  }
};

module.exports = { enrichWithIA };
