/**
 * Sample Test
 * Verifies that Jest and TypeScript are configured correctly
 */

describe('Sample Test Suite', () => {
  it('should pass a basic assertion', () => {
    expect(1 + 1).toBe(2);
  });

  it('should handle async operations', async () => {
    const result = await Promise.resolve(42);
    expect(result).toBe(42);
  });

  it('should use Jest matchers', () => {
    const data = { name: 'test', value: 123 };
    expect(data).toHaveProperty('name');
    expect(data.name).toBe('test');
    expect(data.value).toBeGreaterThan(100);
  });
});
