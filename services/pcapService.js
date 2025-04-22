const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const filePath = path.join(__dirname, '..', 'latest.pcap');

// Fonction utilitaire pour générer un hash SHA256
const generateHash = (buffer) => {
  return crypto.createHash('sha256').update(buffer).digest('hex');
};

const downloadLatestPCAP = async () => {
  try {
    const url = `${process.env.PCAP_API_URL}/pcap/latest`;

    // Télécharger le fichier depuis l'API
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    const newBuffer = response.data;

    if (!newBuffer || newBuffer.length === 0) {
      throw new Error('Le fichier téléchargé est vide.');
    }

    // Générer le hash du fichier téléchargé
    const newHash = generateHash(newBuffer);

    // Vérifier si un fichier existe déjà localement
    if (fs.existsSync(filePath)) {
      const currentBuffer = fs.readFileSync(filePath);
      const currentHash = generateHash(currentBuffer);

      if (newHash === currentHash) {
        console.log("ℹ️ Aucun nouveau fichier PCAP détecté.");
        // Retourner le fichier existant au lieu de null
        return filePath; // Le fichier existant peut être utilisé
      }
    }

    // Écrire le nouveau fichier
    fs.writeFileSync(filePath, newBuffer);
    console.log("✅ Nouveau fichier PCAP téléchargé !");
    return filePath;

  } catch (error) {
    console.error("❌ Erreur lors du téléchargement du fichier PCAP:", error.message);
    throw error; // Relancer l'erreur pour que l'appelant sache qu'il y a eu un problème
  }
};


module.exports = { downloadLatestPCAP };
