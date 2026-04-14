import { Order } from '../../DB/models/order.model.js';
import { Payment } from '../../DB/models/payment.model.js';
import { Shipping } from '../../DB/models/shipping.model.js';
import { Waste } from '../../DB/models/waste.model.js';
import { ensureFactoryForUser } from '../factories/factories.service.js';

export const createOrder = async (user, { wasteId, quantity, shippingAddress, paymentMethod }) => {
  const buyer = await ensureFactoryForUser(user);

  const waste = await Waste.findById(wasteId);
  if (!waste) throw new Error('Waste not found', { cause: 404 });

  const sellerFactoryId = waste.factory;
  const qty = Number(quantity);

  const unitPrice = Number(waste.price);
  const totalAmount = unitPrice * qty;

  const order = await Order.create({
    buyer: buyer._id,
    seller: sellerFactoryId,
    waste: waste._id,
    quantity: qty,
    unitPrice,
    totalAmount,
    currency: waste.currency || 'USD',
    status: 'pending',
  });

  const shipping = await Shipping.create({
    order: order._id,
    address: shippingAddress,
    status: 'pending',
  });

  const payment = await Payment.create({
    order: order._id,
    amount: totalAmount,
    currency: order.currency,
    method: paymentMethod || 'cash',
    status: 'pending',
  });

  return { order, shipping, payment };
};

export const listMyOrders = async (user) => {
  const buyer = await ensureFactoryForUser(user);
  return await Order.find({ buyer: buyer._id })
    .populate('buyer')
    .populate('seller')
    .populate('waste')
    .sort({ createdAt: -1 });
};

export const getOrderById = async (user, orderId) => {
  const buyer = await ensureFactoryForUser(user);
  const order = await Order.findById(orderId).populate('buyer').populate('seller').populate('waste');
  if (!order) throw new Error('Order not found', { cause: 404 });
  if (String(order.buyer._id) !== String(buyer._id)) throw new Error('Forbidden', { cause: 403 });

  const shipping = await Shipping.findOne({ order: order._id });
  const payment = await Payment.findOne({ order: order._id });
  return { order, shipping, payment };
};

