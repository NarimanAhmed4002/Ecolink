const validateCreateNegotiation = (body) => {
  const { wasteId } = body || {};
  if (!wasteId) return 'wasteId is required';
  return null;
};

export { validateCreateNegotiation };

