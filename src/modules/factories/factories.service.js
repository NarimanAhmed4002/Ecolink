import { Factory } from '../../DB/models/factory.model.js';

export const ensureFactoryForUser = async (user) => {
  const existing = await Factory.findOne({ user: user._id });
  if (existing) return existing;

  return await Factory.create({
    user: user._id,
    name: user.name || 'Factory',
  });
};

export const getFactoryByUserId = async (userId) => {
  return await Factory.findOne({ user: userId });
};

