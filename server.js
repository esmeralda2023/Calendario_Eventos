const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');


const app = express();
const port = 3001;
const SECRET_KEY = 'contrasena890';  // Cambia esto a una clave más segura
const cors = require('cors');

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Conectar a la base de datos SQLite
let db = new sqlite3.Database('./agenda.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Conectado a la base de datos SQLite.');
});

// Crear la tabla de eventos si no existe
db.run(`CREATE TABLE IF NOT EXISTS eventos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  titulo TEXT NOT NULL,
  fecha TEXT NOT NULL,
  descripcion TEXT
)`);

// Crear la tabla de usuarios si no existe
db.run(`CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre_usuario TEXT UNIQUE NOT NULL,
  contrasena TEXT NOT NULL
)`);

// Configuración del transportador de correos
const transporter = nodemailer.createTransport({
  service: 'Gmail',  // Puedes usar cualquier servicio de correo compatible con Nodemailer
  auth: {
    user: 'esme1820gs@gmail.com',  // Tu correo electrónico
    pass: 'acabatelo123$'  // Tu contraseña de correo
  }
});

// Función para enviar correos electrónicos
function enviarCorreo(destinatario, asunto, mensaje) {
  const mailOptions = {
    from: 'esme1820gs@gmail.com',
    to: destinatario,
    subject: asunto,
    text: mensaje
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.log('Error al enviar correo:', err);
    } else {
      console.log('Correo enviado: ' + info.response);
    }
  });
}

// Ruta para registrar un nuevo usuario
app.post('/registro', (req, res) => {
  const { nombre_usuario, contrasena } = req.body;
  const saltRounds = 10;

  // Encriptar la contraseña
  bcrypt.hash(contrasena, saltRounds, (err, hash) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    // Guardar el usuario con la contraseña encriptada
    const sql = 'INSERT INTO usuarios (nombre_usuario, contrasena) VALUES (?, ?)';
    db.run(sql, [nombre_usuario, hash], (err) => {
      if (err) {
        res.status(400).json({ error: 'Usuario ya existe o error en la solicitud' });
        return;
      }
      res.json({ mensaje: 'Usuario registrado exitosamente' });
    });
  });
});

// Ruta para login
app.post('/login', (req, res) => {
  const { nombre_usuario, contrasena } = req.body;

  const sql = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  db.get(sql, [nombre_usuario], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!row) {
      res.status(400).json({ error: 'Usuario no encontrado' });
      return;
    }

    // Comparar la contraseña
    bcrypt.compare(contrasena, row.contrasena, (err, result) => {
      if (result) {
        // Crear un token JWT
        const token = jwt.sign({ id: row.id, nombre_usuario: row.nombre_usuario }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ mensaje: 'Login exitoso', token });
      } else {
        res.status(400).json({ error: 'Contraseña incorrecta' });
      }
    });
  });
});

// Middleware para verificar el token JWT
function verificarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ error: 'No se proporcionó un token.' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).send({ error: 'Fallo en la autenticación del token.' });
    req.userId = decoded.id;
    next();
  });
}

// Ruta para obtener todos los eventos
app.get('/eventos', verificarToken, (req, res) => {
  const sql = 'SELECT * FROM eventos';
  db.all(sql, [], (err, rows) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.json({ eventos: rows });
  });
});

// Ruta para agregar un nuevo evento
app.post('/eventos', (req, res) => {
  const { titulo, fecha, descripcion } = req.body;

  // Verificar si ya existe un evento para esa fecha
  const checkSql = 'SELECT * FROM eventos WHERE fecha = ?';
  db.get(checkSql, [fecha], (err, row) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }

    if (row) {
      // Si ya existe un evento para esa fecha, enviar un mensaje de error
      res.status(400).json({ error: 'Ya existe un evento para esta fecha.' });
    } else {
      // Insertar el nuevo evento
      const sql = 'INSERT INTO eventos (titulo, fecha, descripcion) VALUES (?, ?, ?)';
      const params = [titulo, fecha, descripcion];
      db.run(sql, params, function (err) {
        if (err) {
          res.status(400).json({ error: err.message });
          return;
        }
        res.json({
          mensaje: 'Evento agregado exitosamente',
          id: this.lastID,
        });
      });
    }
  });
});

// Ruta para editar un evento
app.put('/eventos/:id', verificarToken, (req, res) => {
  const { id } = req.params;
  const { titulo, fecha, descripcion } = req.body;
  const sql = 'UPDATE eventos SET titulo = ?, fecha = ?, descripcion = ? WHERE id = ?';
  db.run(sql, [titulo, fecha, descripcion, id], function(err) {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.json({ mensaje: 'Evento actualizado exitosamente' });
  });
});

// Ruta para eliminar un evento
app.delete('/eventos/:id', verificarToken, (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM eventos WHERE id = ?';
  db.run(sql, id, function(err) {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.json({ mensaje: 'Evento eliminado exitosamente' });
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});