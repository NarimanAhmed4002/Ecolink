const validateCreateOrder = (body) => {
  const { wasteId, quantity, shippingAddress } = body || {};
  if (!wasteId) return 'wasteId is required';
  if (quantity === undefined || Number.isNaN(Number(quantity))) return 'quantity is required';
  if (Number(quantity) <= 0) return 'quantity must be > 0';
  if (!shippingAddress || !shippingAddress.trim()) return 'shippingAddress is required';
  return null;
};

export { validateCreateOrder };

