var mongoose = require('mongoose');

function connectDB() {
  var mongoUri = process.env.MONGO_URI;

  if (!mongoUri || !mongoUri.trim()) {
    console.error('MONGO_URI manquant dans .env');
    process.exit(1);
  }

  return mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10000 })
    .then(function(connection) {
      console.log('MongoDB connected');
      return connection;
    });
}

module.exports = connectDB;
