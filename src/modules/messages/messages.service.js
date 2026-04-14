import { Message } from '../../DB/models/message.model.js';
import { Negotiation } from '../../DB/models/negotiation.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

export const sendMessage = async (user, { negotiationId, text }) => {
  const factory = await ensureFactoryForUser(user);

  const negotiation = await Negotiation.findById(negotiationId);
  if (!negotiation) throw new Error('Negotiation not found', { cause: 404 });

  const allowed =
    String(negotiation.buyer) === String(factory._id) || String(negotiation.seller) === String(factory._id);
  if (!allowed) throw new Error('Forbidden', { cause: 403 });

  const message = await Message.create({
    negotiation: negotiation._id,
    sender: factory._id,
    text,
  });

  negotiation.lastMessageAt = new Date();
  await negotiation.save();

  return message;
};

export const listMessages = async (user, negotiationId) => {
  const factory = await ensureFactoryForUser(user);
  const negotiation = await Negotiation.findById(negotiationId);
  if (!negotiation) throw new Error('Negotiation not found', { cause: 404 });

  const allowed =
    String(negotiation.buyer) === String(factory._id) || String(negotiation.seller) === String(factory._id);
  if (!allowed) throw new Error('Forbidden', { cause: 403 });

  return await Message.find({ negotiation: negotiation._id }).sort({ createdAt: 1 });
};

