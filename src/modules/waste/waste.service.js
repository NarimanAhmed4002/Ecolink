import { Waste } from '../../DB/models/waste.model.js';
import { WasteCategory } from '../../DB/models/wasteCategory.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

export const createWaste = async (user, payload) => {
  const factory = await ensureFactoryForUser(user);

  const category = await WasteCategory.findById(payload.categoryId);
  if (!category) {
    throw new Error('Waste category not found', { cause: 404 });
  }

  const waste = await Waste.create({
    factory: factory._id,
    category: category._id,
    title: payload.title,
    description: payload.description,
    quantity: Number(payload.quantity),
    unit: payload.unit,
    price: Number(payload.price),
    currency: payload.currency,
    images: payload.images,
    status: payload.status,
  });

  return waste;
};

export const listWaste = async (filters = {}) => {
  const query = {};
  if (filters.factoryId) query.factory = filters.factoryId;
  if (filters.categoryId) query.category = filters.categoryId;
  if (filters.status) query.status = filters.status;

  return await Waste.find(query).populate('factory').populate('category').sort({ createdAt: -1 });
};

export const getWasteById = async (id) => {
  const waste = await Waste.findById(id).populate('factory').populate('category');
  if (!waste) throw new Error('Waste not found', { cause: 404 });
  return waste;
};

export const updateWaste = async (user, wasteId, updates) => {
  const factory = await ensureFactoryForUser(user);
  const waste = await Waste.findById(wasteId);
  if (!waste) throw new Error('Waste not found', { cause: 404 });
  if (String(waste.factory) !== String(factory._id)) throw new Error('Forbidden', { cause: 403 });

  const allowed = ['title', 'description', 'quantity', 'unit', 'price', 'currency', 'images', 'status'];
  for (const key of allowed) {
    if (updates[key] !== undefined) {
      waste[key] = key === 'quantity' || key === 'price' ? Number(updates[key]) : updates[key];
    }
  }

  await waste.save();
  return await Waste.findById(waste._id).populate('factory').populate('category');
};

export const deleteWaste = async (user, wasteId) => {
  const factory = await ensureFactoryForUser(user);
  const waste = await Waste.findById(wasteId);
  if (!waste) throw new Error('Waste not found', { cause: 404 });
  if (String(waste.factory) !== String(factory._id)) throw new Error('Forbidden', { cause: 403 });

  await waste.deleteOne();
  return { success: true };
};

