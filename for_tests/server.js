// Node.js сервер с уязвимостями для тестирования

// Уязвимость: хардкод секретов
const JWT_SECRET = 'my-jwt-secret-key-1234567890';
const DATABASE_PASSWORD = 'MongoDBPass123!';
const API_KEY = 'sk_live_abcdefghijklmnopqrstuvwxyz';

// Уязвимость: уязвимые зависимости в package.json
// "dependencies": {
//   "express": "4.16.0",
//   "mongoose": "5.7.0",
//   "lodash": "4.17.15"
// }

const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());

// Уязвимость: eval с пользовательским вводом
app.post('/eval', (req, res) => {
  const code = req.body.code;
  // Опасное использование eval
  const result = eval(code);
  res.json({ result });
});

// Уязвимость: SQL-инъекция (NoSQL в данном случае)
app.get('/users', (req, res) => {
  const username = req.query.username;
  // Уязвимость NoSQL-инъекции
  const query = { username: username };
  // db.users.find(query) - выполнится с уязвимостью
  res.json({ query });
});

// Уязвимость: выполнение команд
app.post('/exec', (req, res) => {
  const { exec } = require('child_process');
  const command = req.body.command;
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: error.message });
      return;
    }
    res.json({ stdout, stderr });
  });
});

// Уязвимость: небезопасная десериализация
app.post('/deserialize', (req, res) => {
  const serialized = req.body.data;
  // Опасная десериализация
  const obj = JSON.parse(serialized);
  res.json({ obj });
});

// Уязвимость: слабые криптографические алгоритмы
const crypto = require('crypto');
app.post('/hash', (req, res) => {
  const data = req.body.data;
  
  // Слабый MD5
  const md5 = crypto.createHash('md5').update(data).digest('hex');
  
  // Слабый SHA1
  const sha1 = crypto.createHash('sha1').update(data).digest('hex');
  
  res.json({ md5, sha1 });
});

// Уязвимость: небезопасные случайные числа
app.get('/token', (req, res) => {
  // Небезопасная генерация токена
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

// Уязвимость: отключение проверок безопасности
const request = require('request');
app.get('/proxy', (req, res) => {
  const url = req.query.url;
  
  // Отключение SSL проверки
  request.get(url, { rejectUnauthorized: false }, (error, response, body) => {
    if (error) {
      res.status(500).json({ error: error.message });
      return;
    }
    res.send(body);
  });
});

// Уязвимость: CORS - разрешение всем
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  next();
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
