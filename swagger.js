const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Pallad POC API',
      version: '1.0.0',
      description: 'POC pour analyser des fichiers PCAP et enrichir les résultats via IA',
    },
  },
  apis: ['./app.js'], // On documente les routes ici
};

const swaggerSpec = swaggerJsdoc(options);

const setupSwagger = (app) => {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
};

module.exports = setupSwagger;
