/**
 * In-memory policy storage adapter
 * For development and testing
 */

import type { Policy, PolicyStorageAdapter } from '../types';

export class MemoryPolicyStorage implements PolicyStorageAdapter {
  private policies = new Map<string, Policy>();

  async getPolicy(id: string): Promise<Policy | null> {
    return this.policies.get(id) || null;
  }

  async savePolicy(policy: Policy): Promise<void> {
    const now = Date.now();
    const existingPolicy = this.policies.get(policy.id);

    const updatedPolicy: Policy = {
      ...policy,
      createdAt: existingPolicy?.createdAt || now,
      updatedAt: now,
      version: (existingPolicy?.version || 0) + 1,
    };

    this.policies.set(policy.id, updatedPolicy);
  }

  async deletePolicy(id: string): Promise<void> {
    this.policies.delete(id);
  }

  async listPolicies(): Promise<Policy[]> {
    return Array.from(this.policies.values());
  }

  async findPolicies(filter: {
    resourceType?: string;
    action?: string;
    effect?: 'allow' | 'deny';
  }): Promise<Policy[]> {
    const policies = Array.from(this.policies.values());

    return policies.filter((policy) => {
      // Filter by effect
      if (filter.effect && policy.effect !== filter.effect) {
        return false;
      }

      // Filter by resource type and action would require parsing rules
      // For simplicity, we'll use metadata if available
      if (
        filter.resourceType &&
        policy.metadata?.resourceType !== filter.resourceType
      ) {
        return false;
      }

      if (filter.action && policy.metadata?.action !== filter.action) {
        return false;
      }

      return true;
    });
  }

  /**
   * Clear all policies (useful for testing)
   */
  clear(): void {
    this.policies.clear();
  }
}
