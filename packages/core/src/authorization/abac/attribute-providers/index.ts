/**
 * ABAC attribute providers
 * Provides attribute resolution for policy evaluation
 */

import type { AttributeProvider, AttributeValue } from '../types';
import type { UserId, ResourceId } from '../../types';

/**
 * User attribute provider
 * Provides user-related attributes for policy evaluation
 */
export class UserAttributeProvider implements AttributeProvider {
  name = 'user';

  async getAttributes(context: {
    userId?: UserId;
    user?: Record<string, AttributeValue>;
    [key: string]: unknown;
  }): Promise<Record<string, AttributeValue>> {
    // If user attributes are already provided, return them
    if (context.user) {
      return context.user;
    }

    // Otherwise, return minimal attributes
    return {
      id: context.userId || null,
    };
  }
}

/**
 * Resource attribute provider
 * Provides resource-related attributes for policy evaluation
 */
export class ResourceAttributeProvider implements AttributeProvider {
  name = 'resource';

  async getAttributes(context: {
    resourceId?: ResourceId;
    resource?: Record<string, AttributeValue>;
    [key: string]: unknown;
  }): Promise<Record<string, AttributeValue>> {
    // If resource attributes are already provided, return them
    if (context.resource) {
      return context.resource;
    }

    // Otherwise, return minimal attributes
    return {
      id: context.resourceId || null,
    };
  }
}

/**
 * Environment attribute provider
 * Provides environment-related attributes (time, IP, etc.)
 */
export class EnvironmentAttributeProvider implements AttributeProvider {
  name = 'environment';

  getAttributes(context: {
    environment?: Record<string, AttributeValue>;
    [key: string]: unknown;
  }): Record<string, AttributeValue> {
    const now = Date.now();
    const currentHour = new Date().getHours();
    const currentDay = new Date().getDay(); // 0-6, Sunday = 0

    // If environment attributes are provided, merge with defaults
    const provided = context.environment || {};

    const dayNames = [
      'sunday',
      'monday',
      'tuesday',
      'wednesday',
      'thursday',
      'friday',
      'saturday',
    ];
    const dayOfWeek = dayNames[currentDay];

    return {
      timestamp: now,
      currentHour,
      currentDay,
      dayOfWeek: dayOfWeek || 'unknown',
      isWeekend: currentDay === 0 || currentDay === 6,
      isBusinessHours: currentHour >= 9 && currentHour < 17,
      ...provided,
    };
  }
}

/**
 * Custom attribute provider for application-specific attributes
 */
export class CustomAttributeProvider implements AttributeProvider {
  constructor(
    public name: string,
    private resolver: (context: {
      [key: string]: unknown;
    }) =>
      | Promise<Record<string, AttributeValue>>
      | Record<string, AttributeValue>
  ) {}

  async getAttributes(context: {
    [key: string]: unknown;
  }): Promise<Record<string, AttributeValue>> {
    return this.resolver(context);
  }
}

/**
 * Create a custom attribute provider
 */
export function createAttributeProvider(
  name: string,
  resolver: (context: {
    [key: string]: unknown;
  }) => Promise<Record<string, AttributeValue>> | Record<string, AttributeValue>
): AttributeProvider {
  return new CustomAttributeProvider(name, resolver);
}
