/**
 * ABAC policy engine
 * Main policy evaluation engine with caching support
 */

import type {
  Policy,
  PolicyContext,
  PolicyEvaluationResult,
  PolicyEvaluationOptions,
  PolicyCacheEntry,
  AttributeProvider,
  AttributeValue,
} from './types';
import { evaluateRules, countRules } from './rule-evaluator';
import {
  UserAttributeProvider,
  ResourceAttributeProvider,
  EnvironmentAttributeProvider,
} from './attribute-providers';

export interface PolicyEngineOptions {
  /** Attribute providers */
  providers?: AttributeProvider[];
  /** Enable caching by default */
  enableCache?: boolean;
  /** Default cache TTL in milliseconds */
  defaultCacheTTL?: number;
}

export class PolicyEngine {
  private providers: Map<string, AttributeProvider> = new Map();
  private cache: Map<string, PolicyCacheEntry> = new Map();
  private enableCache: boolean;
  private defaultCacheTTL: number;

  constructor(options: PolicyEngineOptions = {}) {
    this.enableCache = options.enableCache ?? true;
    this.defaultCacheTTL = options.defaultCacheTTL ?? 5 * 60 * 1000; // 5 minutes

    // Register default providers
    this.registerProvider(new UserAttributeProvider());
    this.registerProvider(new ResourceAttributeProvider());
    this.registerProvider(new EnvironmentAttributeProvider());

    // Register custom providers
    options.providers?.forEach((provider) => this.registerProvider(provider));
  }

  /**
   * Register an attribute provider
   */
  registerProvider(provider: AttributeProvider): void {
    this.providers.set(provider.name, provider);
  }

  /**
   * Build complete context from providers
   */
  private async buildContext(
    baseContext: Partial<PolicyContext> & { [key: string]: unknown }
  ): Promise<PolicyContext> {
    const context: PolicyContext = {};

    for (const [name, provider] of this.providers.entries()) {
      const attributes = await provider.getAttributes(baseContext);
      context[name] = attributes as Record<string, AttributeValue>;
    }

    return context;
  }

  /**
   * Evaluate a single policy
   */
  async evaluatePolicy(
    policy: Policy,
    context: Partial<PolicyContext> & { [key: string]: unknown },
    options: PolicyEvaluationOptions = {}
  ): Promise<PolicyEvaluationResult> {
    const useCache = options.useCache ?? this.enableCache;
    const cacheTTL = options.cacheTTL ?? this.defaultCacheTTL;

    // Generate cache key
    const cacheKey = this.generateCacheKey(policy.id, context);

    // Check cache
    if (useCache) {
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        return cached;
      }
    }

    // Build full context
    const fullContext = await this.buildContext(context);

    // Evaluate policy
    const startTime = Date.now();
    const matches = evaluateRules(policy.rules, fullContext);
    const endTime = Date.now();

    const totalRules = countRules(policy.rules);

    const result: PolicyEvaluationResult = {
      granted: policy.effect === 'allow' && matches,
      matchedPolicies: matches ? [policy.id] : [],
      decision: matches ? policy.effect : 'not_applicable',
      reason: matches
        ? `Policy ${policy.id} matched (${policy.effect})`
        : `Policy ${policy.id} did not match`,
    };

    // Add optional properties only if they should be included
    if (options.includeDetails) {
      result.context = fullContext;
      result.details = {
        evaluatedRules: totalRules,
        matchedRules: matches ? totalRules : 0,
        evaluationTime: endTime - startTime,
      };
    }

    // Cache result
    if (useCache) {
      this.addToCache(cacheKey, result, cacheTTL);
    }

    return result;
  }

  /**
   * Evaluate multiple policies with combining algorithm
   */
  async evaluatePolicies(
    policies: Policy[],
    context: Partial<PolicyContext> & { [key: string]: unknown },
    options: PolicyEvaluationOptions = {}
  ): Promise<PolicyEvaluationResult> {
    const combiningAlgorithm = options.combiningAlgorithm || 'deny-overrides';
    const results = await Promise.all(
      policies.map((policy) => this.evaluatePolicy(policy, context, options))
    );

    return this.combineResults(results, combiningAlgorithm);
  }

  /**
   * Combine multiple evaluation results using specified algorithm
   */
  private combineResults(
    results: PolicyEvaluationResult[],
    algorithm: 'deny-overrides' | 'allow-overrides' | 'first-applicable'
  ): PolicyEvaluationResult {
    const matchedPolicies = results.flatMap((r) => r.matchedPolicies);

    switch (algorithm) {
      case 'deny-overrides':
        // If any policy denies, result is deny
        if (results.some((r) => r.decision === 'deny')) {
          return {
            granted: false,
            matchedPolicies,
            decision: 'deny',
            reason: 'Denied by deny-overrides algorithm',
          };
        }
        // If any policy allows, result is allow
        if (results.some((r) => r.decision === 'allow')) {
          return {
            granted: true,
            matchedPolicies,
            decision: 'allow',
            reason: 'Allowed by deny-overrides algorithm',
          };
        }
        return {
          granted: false,
          matchedPolicies: [],
          decision: 'not_applicable',
          reason: 'No applicable policies',
        };

      case 'allow-overrides':
        // If any policy allows, result is allow
        if (results.some((r) => r.decision === 'allow')) {
          return {
            granted: true,
            matchedPolicies,
            decision: 'allow',
            reason: 'Allowed by allow-overrides algorithm',
          };
        }
        // If any policy denies, result is deny
        if (results.some((r) => r.decision === 'deny')) {
          return {
            granted: false,
            matchedPolicies,
            decision: 'deny',
            reason: 'Denied by allow-overrides algorithm',
          };
        }
        return {
          granted: false,
          matchedPolicies: [],
          decision: 'not_applicable',
          reason: 'No applicable policies',
        };

      case 'first-applicable': {
        // Return first applicable result
        const firstApplicable = results.find(
          (r) => r.decision !== 'not_applicable'
        );
        if (firstApplicable) {
          return firstApplicable;
        }
        return {
          granted: false,
          matchedPolicies: [],
          decision: 'not_applicable',
          reason: 'No applicable policies',
        };
      }

      default:
        throw new Error(`Unknown combining algorithm: ${algorithm}`);
    }
  }

  /**
   * Generate cache key
   */
  private generateCacheKey(
    policyId: string,
    context: { [key: string]: unknown }
  ): string {
    // Create a deterministic key from policy ID and context
    const contextStr = JSON.stringify(context, Object.keys(context).sort());
    return `${policyId}:${contextStr}`;
  }

  /**
   * Get result from cache
   */
  private getFromCache(key: string): PolicyEvaluationResult | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    // Check expiration
    if (entry.expiresAt < Date.now()) {
      this.cache.delete(key);
      return null;
    }

    return entry.result;
  }

  /**
   * Add result to cache
   */
  private addToCache(
    key: string,
    result: PolicyEvaluationResult,
    ttl: number
  ): void {
    this.cache.set(key, {
      key,
      result,
      expiresAt: Date.now() + ttl,
    });
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Clear expired cache entries
   */
  clearExpiredCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiresAt < now) {
        this.cache.delete(key);
      }
    }
  }
}

/**
 * Create a policy engine instance
 */
export function createPolicyEngine(
  options?: PolicyEngineOptions
): PolicyEngine {
  return new PolicyEngine(options);
}
