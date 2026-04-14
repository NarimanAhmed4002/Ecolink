import { CartItem } from '../../DB/models/cartItem.model.js';
import { ShoppingCart } from '../../DB/models/shoppingCart.model.js';
import { Waste } from '../../DB/models/waste.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

const getOrCreateCart = async (factoryId) => {
  const existing = await ShoppingCart.findOne({ buyer: factoryId });
  if (existing) return existing;
  return await ShoppingCart.create({ buyer: factoryId });
};

export const getCart = async (user) => {
  const factory = await ensureFactoryForUser(user);
  const cart = await getOrCreateCart(factory._id);

  const items = await CartItem.find({ cart: cart._id }).populate('waste');
  return { cart, items };
};

export const addItem = async (user, wasteId, quantity) => {
  const factory = await ensureFactoryForUser(user);
  const cart = await getOrCreateCart(factory._id);

  const waste = await Waste.findById(wasteId);
  if (!waste) throw new Error('Waste not found', { cause: 404 });

  const item = await CartItem.findOneAndUpdate(
    { cart: cart._id, waste: waste._id },
    { $set: { cart: cart._id, waste: waste._id }, $inc: { quantity: Number(quantity) } },
    { new: true, upsert: true }
  ).populate('waste');

  return item;
};

export const updateItem = async (user, wasteId, quantity) => {
  const factory = await ensureFactoryForUser(user);
  const cart = await getOrCreateCart(factory._id);

  const item = await CartItem.findOneAndUpdate(
    { cart: cart._id, waste: wasteId },
    { $set: { quantity: Number(quantity) } },
    { new: true }
  ).populate('waste');

  if (!item) throw new Error('Cart item not found', { cause: 404 });
  return item;
};

export const removeItem = async (user, wasteId) => {
  const factory = await ensureFactoryForUser(user);
  const cart = await getOrCreateCart(factory._id);

  const item = await CartItem.findOneAndDelete({ cart: cart._id, waste: wasteId });
  if (!item) throw new Error('Cart item not found', { cause: 404 });

  return { success: true };
};
