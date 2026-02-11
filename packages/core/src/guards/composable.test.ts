/**
 * @amtarc/auth-utils - Composable Guards Tests
 */

import { describe, it, expect } from 'vitest';
import {
  requireAny,
  requireAll,
  chainGuards,
  allowAll,
  denyAll,
  conditionalGuard,
} from './composable';
import type { GuardContext, GuardFunction, GuardResult } from './require-auth';

// Mock guards for testing
function createPassGuard<T>(data?: T): GuardFunction<T> {
  return async (): Promise<GuardResult<T>> => ({
    authorized: true,
    data,
  });
}

function createFailGuard(message?: string, redirect?: string): GuardFunction {
  return async (): Promise<GuardResult> => ({
    authorized: false,
    message: message || 'Guard failed',
    redirect,
  });
}

function createMockContext(): GuardContext {
  return {
    getSession: async () => null,
  };
}

describe('requireAny', () => {
  it('should pass if one guard passes', async () => {
    const guard = requireAny([
      createFailGuard('First failed'),
      createPassGuard('success'),
      createFailGuard('Third failed'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('success');
  });

  it('should pass if all guards pass', async () => {
    const guard = requireAny([
      createPassGuard('first'),
      createPassGuard('second'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
  });

  it('should fail if all guards fail', async () => {
    const guard = requireAny([
      createFailGuard('First failed'),
      createFailGuard('Second failed'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toContain('None of the required conditions');
  });

  it('should fail with empty guards array', async () => {
    const guard = requireAny([]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toContain('No guards provided');
  });

  it('should return first passing guard result', async () => {
    const guard = requireAny([
      createFailGuard(),
      createPassGuard('first-pass'),
      createPassGuard('second-pass'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('first-pass');
  });
});

describe('requireAll', () => {
  it('should pass if all guards pass', async () => {
    const guard = requireAll([
      createPassGuard('first'),
      createPassGuard('second'),
      createPassGuard('third'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toEqual(['first', 'second', 'third']);
  });

  it('should fail if one guard fails', async () => {
    const guard = requireAll([
      createPassGuard(),
      createFailGuard('Middle guard failed'),
      createPassGuard(),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toBe('Middle guard failed');
  });

  it('should pass with empty guards array', async () => {
    const guard = requireAll([]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toEqual([]);
  });

  it('should include redirect from failed guard', async () => {
    const guard = requireAll([
      createPassGuard(),
      createFailGuard('Auth required', '/login'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.redirect).toBe('/login');
  });

  it('should filter out undefined data', async () => {
    const guard = requireAll([
      createPassGuard('data1'),
      createPassGuard(undefined),
      createPassGuard('data2'),
    ]);

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toEqual(['data1', 'data2']);
  });
});

describe('chainGuards', () => {
  it('should execute guards sequentially', async () => {
    const order: number[] = [];

    const guard1: GuardFunction = async () => {
      order.push(1);
      return { authorized: true };
    };

    const guard2: GuardFunction = async () => {
      order.push(2);
      return { authorized: true };
    };

    const guard3: GuardFunction = async () => {
      order.push(3);
      return { authorized: true };
    };

    const guard = chainGuards(guard1, guard2, guard3);
    await guard(createMockContext());

    expect(order).toEqual([1, 2, 3]);
  });

  it('should short-circuit on first failure', async () => {
    const order: number[] = [];

    const guard1: GuardFunction = async () => {
      order.push(1);
      return { authorized: true };
    };

    const guard2: GuardFunction = async () => {
      order.push(2);
      return { authorized: false, message: 'Failed at 2' };
    };

    const guard3: GuardFunction = async () => {
      order.push(3);
      return { authorized: true };
    };

    const guard = chainGuards(guard1, guard2, guard3);
    const result = await guard(createMockContext());

    expect(order).toEqual([1, 2]); // guard3 never called
    expect(result.authorized).toBe(false);
    expect(result.message).toBe('Failed at 2');
  });

  it('should pass with empty guards', async () => {
    const guard = chainGuards();
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
  });

  it('should return last guard data', async () => {
    const guard = chainGuards(
      createPassGuard('first'),
      createPassGuard('second'),
      createPassGuard('third')
    );

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('third');
  });
});

describe('allowAll', () => {
  it('should always pass', async () => {
    const guard = allowAll();
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
  });

  it('should pass with data', async () => {
    const guard = allowAll({ message: 'allowed' });
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toEqual({ message: 'allowed' });
  });
});

describe('denyAll', () => {
  it('should always fail', async () => {
    const guard = denyAll();
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toBe('Access denied');
  });

  it('should use custom message', async () => {
    const guard = denyAll({ message: 'Maintenance mode' });
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toBe('Maintenance mode');
  });

  it('should include redirect', async () => {
    const guard = denyAll({ redirect: '/maintenance' });
    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.redirect).toBe('/maintenance');
  });
});

describe('conditionalGuard', () => {
  it('should apply guard when condition is true', async () => {
    const guard = conditionalGuard(true, createFailGuard('Guard applied'));

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(false);
    expect(result.message).toBe('Guard applied');
  });

  it('should skip guard when condition is false', async () => {
    const guard = conditionalGuard(false, createFailGuard('Should not run'));

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
  });

  it('should use fallback when condition is false', async () => {
    const guard = conditionalGuard(
      false,
      createFailGuard('Main guard'),
      createPassGuard('fallback-data')
    );

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('fallback-data');
  });

  it('should support function condition', async () => {
    const guard = conditionalGuard(
      () => true,
      createPassGuard('function-condition')
    );

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('function-condition');
  });

  it('should support async function condition', async () => {
    const guard = conditionalGuard(
      async () => Promise.resolve(true),
      createPassGuard('async-condition')
    );

    const result = await guard(createMockContext());

    expect(result.authorized).toBe(true);
    expect(result.data).toBe('async-condition');
  });
});
