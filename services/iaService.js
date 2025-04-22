const axios = require('axios');
require('dotenv').config();

const enrichWithIA = async (input) => {
    const response = await axios.post(
      `${process.env.MISTRAL_API_URL}/chat/completions`,
      {
        model: "mistral-nemo-instruct-2407",
        messages: [
          { role: "system", content: "Vous êtes un assistant de sécurité informatique et vous analysez les fichiers de logs." },
          { role: "user", content: `Voici l'analyse d'un fichier PCAP : ${input}` },
        ],
        max_tokens: 256,
        temperature: 0.3,
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
  };
  
  

module.exports = { enrichWithIA };
