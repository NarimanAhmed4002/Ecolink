const validateCreateReview = (body) => {
  const { factoryId, rating } = body || {};
  if (!factoryId) return 'factoryId is required';
  if (rating === undefined || Number.isNaN(Number(rating))) return 'rating is required';
  const r = Number(rating);
  if (r < 1 || r > 5) return 'rating must be between 1 and 5';
  return null;
};

export { validateCreateReview };

