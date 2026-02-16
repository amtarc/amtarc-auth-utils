/**
 * ABAC (Attribute-Based Access Control) types
 * Provides policy-based authorization using attributes
 */

import type { UserId, ResourceId, AuthorizationResult } from '../types';

/**
 * Comparison operators for attribute evaluation
 */
export type ComparisonOperator =
  | 'eq' // Equal
  | 'neq' // Not equal
  | 'gt' // Greater than
  | 'gte' // Greater than or equal
  | 'lt' // Less than
  | 'lte' // Less than or equal
  | 'in' // In array
  | 'notIn' // Not in array
  | 'contains' // Array contains
  | 'notContains' // Array not contains
  | 'startsWith' // String starts with
  | 'endsWith' // String ends with
  | 'matches'; // Regex match

/**
 * Logical operators for combining rules
 */
export type LogicalOperator = 'AND' | 'OR' | 'NOT';

/**
 * Attribute value types
 */
export type AttributeValue =
  | string
  | number
  | boolean
  | null
  | AttributeValue[];

/**
 * Attributes for ABAC evaluation
 */
export interface Attributes {
  user?: Record<string, AttributeValue>;
  resource?: Record<string, AttributeValue>;
  environment?: Record<string, AttributeValue>;
  [key: string]: Record<string, AttributeValue> | undefined;
}

/**
 * Single rule condition
 */
export interface Rule {
  /** Attribute path (e.g., 'user.role', 'resource.owner') */
  attribute: string;
  /** Comparison operator */
  operator: ComparisonOperator;
  /** Value to compare against */
  value: AttributeValue;
  /** Optional description */
  description?: string;
}

/**
 * Rule group with logical operator
 */
export interface RuleGroup {
  /** Logical operator for combining rules */
  operator: LogicalOperator;
  /** Rules or nested groups */
  rules: (Rule | RuleGroup)[];
  /** Optional description */
  description?: string;
}

/**
 * Policy definition
 */
export interface Policy {
  /** Unique policy identifier */
  id: string;
  /** Policy name */
  name: string;
  /** Policy description */
  description?: string;
  /** Effect when policy matches */
  effect: 'allow' | 'deny';
  /** Root rule or rule group */
  rules: Rule | RuleGroup;
  /** Policy metadata */
  metadata?: Record<string, unknown>;
  /** Policy version */
  version?: number;
  /** Creation timestamp */
  createdAt?: number;
  /** Last update timestamp */
  updatedAt?: number;
}

/**
 * Policy evaluation context
 */
export interface PolicyContext {
  /** User attributes */
  user?: Record<string, AttributeValue>;
  /** Resource attributes */
  resource?: Record<string, AttributeValue>;
  /** Environment attributes (time, IP, etc.) */
  environment?: Record<string, AttributeValue>;
  /** Additional custom attributes */
  [key: string]: Record<string, AttributeValue> | undefined;
}

/**
 * Policy evaluation result
 */
export interface PolicyEvaluationResult extends AuthorizationResult {
  /** Matched policies */
  matchedPolicies: string[];
  /** Final decision */
  decision: 'allow' | 'deny' | 'not_applicable';
  /** Evaluation details */
  details?: {
    /** Evaluated rules */
    evaluatedRules: number;
    /** Matched rules */
    matchedRules: number;
    /** Evaluation time in ms */
    evaluationTime?: number;
  };
}

/**
 * Attribute provider interface
 */
export interface AttributeProvider {
  /** Provider name */
  name: string;
  /** Get attributes for context */
  getAttributes(context: {
    userId?: UserId;
    resourceId?: ResourceId;
    [key: string]: unknown;
  }): Promise<Record<string, AttributeValue>> | Record<string, AttributeValue>;
}

/**
 * Policy storage interface
 */
export interface PolicyStorageAdapter {
  /** Get policy by ID */
  getPolicy(id: string): Promise<Policy | null>;
  /** Save policy */
  savePolicy(policy: Policy): Promise<void>;
  /** Delete policy */
  deletePolicy(id: string): Promise<void>;
  /** List all policies */
  listPolicies(): Promise<Policy[]>;
  /** Find policies by resource type or action */
  findPolicies(filter: {
    resourceType?: string;
    action?: string;
    effect?: 'allow' | 'deny';
  }): Promise<Policy[]>;
}

/**
 * Policy evaluation options
 */
export interface PolicyEvaluationOptions {
  /** Use cached results if available */
  useCache?: boolean;
  /** Cache TTL in milliseconds */
  cacheTTL?: number;
  /** Include evaluation details in result */
  includeDetails?: boolean;
  /** Policy combination strategy */
  combiningAlgorithm?:
    | 'deny-overrides'
    | 'allow-overrides'
    | 'first-applicable';
}

/**
 * Policy cache entry
 */
export interface PolicyCacheEntry {
  /** Cache key */
  key: string;
  /** Evaluation result */
  result: PolicyEvaluationResult;
  /** Expiration timestamp */
  expiresAt: number;
}
