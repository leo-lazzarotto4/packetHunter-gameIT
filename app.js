const express = require('express');
const dotenv = require('dotenv');
const { downloadLatestPCAP } = require('./services/pcapService');
const { enrichWithIA } = require('./services/iaService');
const setupSwagger = require('./swagger');
const dns = require('dns');
const axios = require('axios');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const cors = require('cors');


dotenv.config();
const app = express();
const PORT = 3000;

app.use(cors());

// Swagger docs setup
setupSwagger(app);

/**
 * @swagger
 * /analyze:
 *   get:
 *     summary: Télécharge, analyse et enrichit un fichier PCAP
 *     description: Télécharge le dernier fichier PCAP, analyse son contenu, et renvoie les résultats enrichis par l'IA.
 *     responses:
 *       200:
 *         description: Résultat enrichi avec l'IA et alertes possibles
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indique si l'opération a réussi
 *                 analysis:
 *                   type: string
 *                   description: Résumé de l'analyse du fichier PCAP
 *                 ia_response:
 *                   type: string
 *                   description: Réponse enrichie par l'IA
 *                 alert:
 *                   type: string
 *                   description: Alerte en cas d'anomalie détectée (optionnelle)
 *       500:
 *         description: Erreur lors de l'analyse
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Détail de l'erreur
 */

// Utilitaire pour savoir si l'IP est privée
const isPrivateIP = (ip) => {
  const ipParts = ip.split('.').map(Number);
  return (
    ipParts[0] === 10 ||
    (ipParts[0] === 172 && ipParts[1] >= 16 && ipParts[1] <= 31) ||
    (ipParts[0] === 192 && ipParts[1] === 168)
  );
};

// DNS reverse uniquement pour IP publiques
const getHostnameFromIP = (ip) => {
  return new Promise((resolve, reject) => {
    if (isPrivateIP(ip)) {
      resolve(null); // On garde celui de l'analyse
    } else {
      dns.reverse(ip, (err, hostnames) => {
        if (err) {
          resolve(null);
        } else {
          resolve(hostnames[0] || null);
        }
      });
    }
  });
};

// Appel du script Python d’analyse
const runPythonAnalysis = (pcapPath) => {
  return new Promise((resolve, reject) => {
    const outputPath = path.join(__dirname, 'network_hosts.json');
    const scriptPath = path.join(__dirname, 'services', 'analyzeService.py');

    execFile('python3', [scriptPath, '-p', pcapPath, '-o', outputPath], (error, stdout, stderr) => {
      if (error) {
        console.error('Erreur analyse Python:', error);
        return reject(error);
      }

      fs.readFile(outputPath, 'utf8', (err, data) => {
        if (err) return reject(err);
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (e) {
          reject(new Error('Erreur parsing JSON'));
        }
      });
    });
  });
};

app.get('/analyze', async (req, res) => {
  try {
    const filePath = await downloadLatestPCAP();
    const analysisResult = await runPythonAnalysis(filePath);
    console.log("🎯 Analyse :", analysisResult);

    // On prend le premier hôte détecté (par défaut)
    const firstKey = Object.keys(analysisResult)[0];
    const device = analysisResult[firstKey];
    const { ip, mac, hostname, username } = device;

    const resolvedHostname = await getHostnameFromIP(ip);
    const finalHostname = resolvedHostname || hostname;

    // Enrichissement IA
    const enriched = await enrichWithIA(analysisResult);

    // Préparation payload pour le POST
    const payload = {
      user_id: "llazzarotto",
      lines: [
        mac,
        ip,
        finalHostname,
        username
      ]
    };

    const response = await axios.post(`${process.env.PCAP_API_URL}/pcap/submit`, payload, {
      headers: {
      }
    });

    res.json({
      success: true,
      analysis: analysisResult,
      ia_response: enriched,
      api_response: response.data
    });

  } catch (error) {
    console.error("❌ Erreur :", error.message);
    res.status(500).json({ error: "Erreur lors de l'analyse ou de l'envoi des données" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur : http://localhost:${PORT}`);
  console.log(`📚 Swagger dispo sur : http://localhost:${PORT}/api-docs`);
});