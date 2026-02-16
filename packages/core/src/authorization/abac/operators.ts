/**
 * ABAC comparison operators
 * Implements all comparison logic for attribute evaluation
 */

import type { AttributeValue, ComparisonOperator } from './types';

/**
 * Evaluate a comparison between two values
 */
export function evaluateComparison(
  left: AttributeValue,
  operator: ComparisonOperator,
  right: AttributeValue
): boolean {
  switch (operator) {
    case 'eq':
      return equals(left, right);
    case 'neq':
      return !equals(left, right);
    case 'gt':
      return greaterThan(left, right);
    case 'gte':
      return greaterThanOrEqual(left, right);
    case 'lt':
      return lessThan(left, right);
    case 'lte':
      return lessThanOrEqual(left, right);
    case 'in':
      return isIn(left, right);
    case 'notIn':
      return !isIn(left, right);
    case 'contains':
      return contains(left, right);
    case 'notContains':
      return !contains(left, right);
    case 'startsWith':
      return startsWith(left, right);
    case 'endsWith':
      return endsWith(left, right);
    case 'matches':
      return matches(left, right);
    default:
      throw new Error(`Unknown operator: ${operator}`);
  }
}

/**
 * Deep equality check
 */
function equals(left: AttributeValue, right: AttributeValue): boolean {
  if (left === right) return true;
  if (left === null || right === null) return false;

  if (Array.isArray(left) && Array.isArray(right)) {
    if (left.length !== right.length) return false;
    return left.every((val, idx) => {
      const rightVal = right[idx];
      return rightVal !== undefined && equals(val, rightVal);
    });
  }

  return left === right;
}

/**
 * Greater than comparison
 */
function greaterThan(left: AttributeValue, right: AttributeValue): boolean {
  if (typeof left === 'number' && typeof right === 'number') {
    return left > right;
  }
  if (typeof left === 'string' && typeof right === 'string') {
    return left > right;
  }
  return false;
}

/**
 * Greater than or equal comparison
 */
function greaterThanOrEqual(
  left: AttributeValue,
  right: AttributeValue
): boolean {
  return equals(left, right) || greaterThan(left, right);
}

/**
 * Less than comparison
 */
function lessThan(left: AttributeValue, right: AttributeValue): boolean {
  if (typeof left === 'number' && typeof right === 'number') {
    return left < right;
  }
  if (typeof left === 'string' && typeof right === 'string') {
    return left < right;
  }
  return false;
}

/**
 * Less than or equal comparison
 */
function lessThanOrEqual(left: AttributeValue, right: AttributeValue): boolean {
  return equals(left, right) || lessThan(left, right);
}

/**
 * Check if value is in array
 */
function isIn(value: AttributeValue, array: AttributeValue): boolean {
  if (!Array.isArray(array)) return false;
  return array.some((item) => equals(value, item));
}

/**
 * Check if array contains value
 */
function contains(array: AttributeValue, value: AttributeValue): boolean {
  if (!Array.isArray(array)) return false;
  return array.some((item) => equals(item, value));
}

/**
 * Check if string starts with value
 */
function startsWith(str: AttributeValue, prefix: AttributeValue): boolean {
  if (typeof str !== 'string' || typeof prefix !== 'string') return false;
  return str.startsWith(prefix);
}

/**
 * Check if string ends with value
 */
function endsWith(str: AttributeValue, suffix: AttributeValue): boolean {
  if (typeof str !== 'string' || typeof suffix !== 'string') return false;
  return str.endsWith(suffix);
}

/**
 * Check if string matches regex pattern
 */
function matches(str: AttributeValue, pattern: AttributeValue): boolean {
  if (typeof str !== 'string' || typeof pattern !== 'string') return false;
  try {
    const regex = new RegExp(pattern);
    return regex.test(str);
  } catch {
    return false;
  }
}
