const validateCreateWaste = (body) => {
  const { title, categoryId, quantity, price } = body || {};
  if (!title || !title.trim()) return 'Title is required';
  if (!categoryId) return 'categoryId is required';
  if (quantity === undefined || Number.isNaN(Number(quantity))) return 'quantity is required';
  if (Number(quantity) < 0) return 'quantity must be >= 0';
  if (price === undefined || Number.isNaN(Number(price))) return 'price is required';
  if (Number(price) < 0) return 'price must be >= 0';
  return null;
};

const validateUpdateWaste = (body) => {
  const { quantity, price, title } = body || {};
  if (title !== undefined && (!title || !title.trim())) return 'title cannot be empty';
  if (quantity !== undefined && (Number.isNaN(Number(quantity)) || Number(quantity) < 0))
    return 'quantity must be a number >= 0';
  if (price !== undefined && (Number.isNaN(Number(price)) || Number(price) < 0))
    return 'price must be a number >= 0';
  return null;
};

export { validateCreateWaste, validateUpdateWaste };

