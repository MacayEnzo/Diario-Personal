const express = require('express');
const cors = require('cors');
const app = express();
const routes = require('./routes');

require('dotenv').config();

// Middleware
app.use(cors());
app.use(express.json());

// Rutas
app.use('/api', routes);
    
  

// Arrancar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
