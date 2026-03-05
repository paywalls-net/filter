export default {
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.js'],
  // ESM transform: jest uses --experimental-vm-modules via the npm script
  transform: {},
};
