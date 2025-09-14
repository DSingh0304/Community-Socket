import jwt from 'jsonwebtoken';

export function verifyToken(token) {
  try {
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      console.error('JWT_SECRET not found in environment');
      return null;
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('JWT verification successful for user:', decoded.userId);
    return decoded;
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return null;
  }
}