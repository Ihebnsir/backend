var mongoose = require('mongoose');

function connectDB() {
  var mongoUri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/seculens';

  return mongoose.connect(mongoUri);
}

module.exports = connectDB;
