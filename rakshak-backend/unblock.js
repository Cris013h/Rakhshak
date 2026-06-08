import mongoose from 'mongoose';

await mongoose.connect('mongodb://localhost:27017/rakshak');
const result = await mongoose.connection.collection('firewalllogs').updateMany({}, { $set: { status: 'Unblocked' } });
console.log('Done:', result.modifiedCount, 'records unblocked');
process.exit();