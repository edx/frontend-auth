const mockCookiesImplementation = {
  get: jest.fn(),
};

module.exports = () => mockCookiesImplementation;
