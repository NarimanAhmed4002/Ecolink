import { Negotiation } from '../../DB/models/negotiation.model.js';
import { Waste } from '../../DB/models/waste.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

export const createNegotiation = async (user, wasteId) => {
  const buyer = await ensureFactoryForUser(user);
  const waste = await Waste.findById(wasteId);
  if (!waste) throw new Error('Waste not found', { cause: 404 });

  const seller = waste.factory;

  const existing = await Negotiation.findOne({
    buyer: buyer._id,
    seller,
    waste: waste._id,
    status: 'open',
  });
  if (existing) return existing;

  return await Negotiation.create({
    buyer: buyer._id,
    seller,
    waste: waste._id,
    status: 'open',
    lastMessageAt: new Date(),
    currency: waste.currency || 'USD',
  });
};

export const listMyNegotiations = async (user) => {
  const factory = await ensureFactoryForUser(user);
  return await Negotiation.find({
    $or: [{ buyer: factory._id }, { seller: factory._id }],
  })
    .populate('buyer')
    .populate('seller')
    .populate('waste')
    .sort({ updatedAt: -1 });
};

export const getNegotiationById = async (user, negotiationId) => {
  const factory = await ensureFactoryForUser(user);
  const negotiation = await Negotiation.findById(negotiationId)
    .populate('buyer')
    .populate('seller')
    .populate('waste');
  if (!negotiation) throw new Error('Negotiation not found', { cause: 404 });
  const allowed =
    String(negotiation.buyer._id) === String(factory._id) ||
    String(negotiation.seller._id) === String(factory._id);
  if (!allowed) throw new Error('Forbidden', { cause: 403 });
  return negotiation;
};

