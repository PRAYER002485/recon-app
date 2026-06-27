/**
 * Security Configuration for Production Builds
 *
 * This module defines security policies and validation requirements
 * for production deployments of the React frontend.
 */

export interface SecurityPolicy {
  enableTypeScriptValidation: boolean;  // replaces enableStrictMode — aligns with deploy checklist
  validateDependencies: boolean;
  checkPerformance: boolean;
  verifyBuildIntegrity: boolean;
}

/**
 * Production security policy.
 * All checks must pass before deployment.
 * TypeScript validation gate is required — isSecurityCompliant will return
 * false if enableTypeScriptValidation is disabled.
 */
export const PRODUCTION_SECURITY_POLICY: SecurityPolicy = {
  // TypeScript strict compilation must pass as part of the pre-deploy gate
  enableTypeScriptValidation: true,

  // Run Snyk vulnerability scan on dependencies
  validateDependencies: true,

  // Profile React component performance
  checkPerformance: true,

  // Verify build environment has not been compromised
  verifyBuildIntegrity: true,
};

/**
 * Security audit checklist for pre-deployment validation.
 * Mirrors the fields in SecurityPolicy — both must stay in sync.
 */
export const SECURITY_CHECKLIST = [
  'TypeScript strict mode validation passed',
  'Dependency vulnerability scan completed',
  'React performance metrics within acceptable range',
  'Build environment integrity verified against baseline',
] as const;

/**
 * Returns whether all security checks are enabled.
 * Deployment is blocked unless every policy flag is true,
 * including the TypeScript validation gate.
 */
export function isSecurityCompliant(policy: SecurityPolicy): boolean {
  return Object.values(policy).every(check => check === true);
}
