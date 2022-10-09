const mongoose = require("mongoose");

module.exports = async () => {
    try {console.log(`Database connection Established`);
    
        await mongoose.connect(process.env.DB_URL, { useNewUrlParser: true, useUnifiedTopology: true });
    } catch (error) {
        console.log(`Unable to connect to mongodb Database: ${error}`)
    }
}
