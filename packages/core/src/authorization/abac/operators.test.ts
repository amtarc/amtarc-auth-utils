import { describe, it, expect } from 'vitest';
import { evaluateComparison } from './operators';

describe('ABAC Operators', () => {
  describe('eq (equals)', () => {
    it('compares primitive values', () => {
      expect(evaluateComparison('admin', 'eq', 'admin')).toBe(true);
      expect(evaluateComparison(42, 'eq', 42)).toBe(true);
      expect(evaluateComparison(true, 'eq', true)).toBe(true);
      expect(evaluateComparison('admin', 'eq', 'user')).toBe(false);
    });

    it('compares arrays', () => {
      expect(evaluateComparison([1, 2, 3], 'eq', [1, 2, 3])).toBe(true);
      expect(evaluateComparison([1, 2], 'eq', [1, 2, 3])).toBe(false);
    });

    it('handles null', () => {
      expect(evaluateComparison(null, 'eq', null)).toBe(true);
      expect(evaluateComparison(null, 'eq', 'value')).toBe(false);
    });
  });

  describe('neq (not equals)', () => {
    it('compares primitive values', () => {
      expect(evaluateComparison('admin', 'neq', 'user')).toBe(true);
      expect(evaluateComparison(42, 'neq', 43)).toBe(true);
      expect(evaluateComparison('admin', 'neq', 'admin')).toBe(false);
    });
  });

  describe('gt (greater than)', () => {
    it('compares numbers', () => {
      expect(evaluateComparison(10, 'gt', 5)).toBe(true);
      expect(evaluateComparison(5, 'gt', 10)).toBe(false);
      expect(evaluateComparison(5, 'gt', 5)).toBe(false);
    });

    it('compares strings', () => {
      expect(evaluateComparison('b', 'gt', 'a')).toBe(true);
      expect(evaluateComparison('a', 'gt', 'b')).toBe(false);
    });
  });

  describe('gte (greater than or equal)', () => {
    it('compares numbers', () => {
      expect(evaluateComparison(10, 'gte', 5)).toBe(true);
      expect(evaluateComparison(5, 'gte', 5)).toBe(true);
      expect(evaluateComparison(3, 'gte', 5)).toBe(false);
    });
  });

  describe('lt (less than)', () => {
    it('compares numbers', () => {
      expect(evaluateComparison(5, 'lt', 10)).toBe(true);
      expect(evaluateComparison(10, 'lt', 5)).toBe(false);
      expect(evaluateComparison(5, 'lt', 5)).toBe(false);
    });
  });

  describe('lte (less than or equal)', () => {
    it('compares numbers', () => {
      expect(evaluateComparison(5, 'lte', 10)).toBe(true);
      expect(evaluateComparison(5, 'lte', 5)).toBe(true);
      expect(evaluateComparison(10, 'lte', 5)).toBe(false);
    });
  });

  describe('in (value in array)', () => {
    it('checks if value is in array', () => {
      expect(
        evaluateComparison('admin', 'in', ['admin', 'user', 'guest'])
      ).toBe(true);
      expect(evaluateComparison('superadmin', 'in', ['admin', 'user'])).toBe(
        false
      );
    });

    it('returns false for non-array', () => {
      expect(evaluateComparison('admin', 'in', 'admin')).toBe(false);
    });
  });

  describe('notIn (value not in array)', () => {
    it('checks if value is not in array', () => {
      expect(evaluateComparison('superadmin', 'notIn', ['admin', 'user'])).toBe(
        true
      );
      expect(evaluateComparison('admin', 'notIn', ['admin', 'user'])).toBe(
        false
      );
    });
  });

  describe('contains (array contains value)', () => {
    it('checks if array contains value', () => {
      expect(evaluateComparison(['admin', 'user'], 'contains', 'admin')).toBe(
        true
      );
      expect(evaluateComparison(['admin', 'user'], 'contains', 'guest')).toBe(
        false
      );
    });

    it('returns false for non-array', () => {
      expect(evaluateComparison('admin', 'contains', 'admin')).toBe(false);
    });
  });

  describe('notContains (array not contains value)', () => {
    it('checks if array does not contain value', () => {
      expect(
        evaluateComparison(['admin', 'user'], 'notContains', 'guest')
      ).toBe(true);
      expect(
        evaluateComparison(['admin', 'user'], 'notContains', 'admin')
      ).toBe(false);
    });
  });

  describe('startsWith (string starts with)', () => {
    it('checks if string starts with prefix', () => {
      expect(
        evaluateComparison('admin@example.com', 'startsWith', 'admin')
      ).toBe(true);
      expect(
        evaluateComparison('user@example.com', 'startsWith', 'admin')
      ).toBe(false);
    });

    it('returns false for non-string', () => {
      expect(evaluateComparison(123, 'startsWith', 'admin')).toBe(false);
    });
  });

  describe('endsWith (string ends with)', () => {
    it('checks if string ends with suffix', () => {
      expect(evaluateComparison('admin@example.com', 'endsWith', '.com')).toBe(
        true
      );
      expect(evaluateComparison('admin@example.org', 'endsWith', '.com')).toBe(
        false
      );
    });

    it('returns false for non-string', () => {
      expect(evaluateComparison(123, 'endsWith', '.com')).toBe(false);
    });
  });

  describe('matches (regex match)', () => {
    it('checks if string matches pattern', () => {
      expect(
        evaluateComparison('admin@example.com', 'matches', '^[a-z]+@')
      ).toBe(true);
      expect(
        evaluateComparison('Admin@example.com', 'matches', '^[a-z]+@')
      ).toBe(false);
      expect(evaluateComparison('test123', 'matches', '\\d+')).toBe(true);
    });

    it('returns false for invalid regex', () => {
      expect(evaluateComparison('test', 'matches', '[invalid')).toBe(false);
    });

    it('returns false for non-string', () => {
      expect(evaluateComparison(123, 'matches', '\\d+')).toBe(false);
    });
  });

  describe('unknown operator', () => {
    it('throws error for unknown operator', () => {
      expect(() =>
        evaluateComparison('value', 'unknown' as any, 'test')
      ).toThrow('Unknown operator');
    });
  });
});
