import { Auth } from '../DB/models/auth.model.js';
import { User } from '../DB/models/user.model.js';
import { verifyToken } from '../utils/token/index.js';

export const isAuthenticated = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error('Token is required.', { cause: 401 });
    }

    const token = authHeader.split(' ')[1];

    const payload = verifyToken(token); // throws if invalid/expired

    const blockedToken = await Auth.findOne({ token, type: 'access' });
    if (blockedToken) {
      throw new Error('Token is invalid.', { cause: 401 });
    }

    const userExist = await User.findById(payload.id);
    if (!userExist) {
      throw new Error('User is not found', { cause: 404 });
    }

    if (
      userExist.credentialsUpdatedAt &&
      payload.iat &&
      userExist.credentialsUpdatedAt > new Date(payload.iat * 1000)
    ) {
      throw new Error('Token is expired!', { cause: 401 });
    }

    req.user = userExist;
    return next();
  } catch (error) {
    next(error);
  }
};
