const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/aicte_pramaan', {
            family: 4 // Force IPv4
        });
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Database Connection Error: ${error.message}`);
        console.log('Server will continue running, but DB operations will fail until MongoDB is active.');
    }
};

module.exports = connectDB;