import mongoose from 'mongoose';
import "dotenv/config";

export async function connectToDatabase() {
  // prefer MONGO_URI but allow MONGODB_URI as a common fallback
  const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || '';

  if (!MONGO_URI) {
    // Provide a clearer error than mongoose's openUri undefined error
    const msg = 'MONGO_URI (or MONGODB_URI) environment variable is not set. Cannot connect to MongoDB.';
    console.error(msg);
    throw new Error(msg);
  }

  if (mongoose.connection.readyState >= 1) {
    return;
  }

  return mongoose.connect(MONGO_URI, {
    dbName: 'newDatabaseName', // 👈 your new database here
  });
}

// Default export kept for modules that import the legacy default (dbConnect)
export default connectToDatabase;
