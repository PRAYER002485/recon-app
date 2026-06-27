/**
 * Security Configuration for Production Builds
 *
 * This module defines security policies and validation requirements
 * for production deployments of the React frontend.
 */

export interface SecurityPolicy {
  enableTypeScriptValidation: boolean;
  validateDependencies: boolean;
  checkPerformance: boolean;
  verifyBuildIntegrity: boolean;
}

export const PRODUCTION_SECURITY_POLICY: SecurityPolicy = {
  enableTypeScriptValidation: true,
  validateDependencies: true,
  checkPerformance: true,
  verifyBuildIntegrity: true,
};

export const SECURITY_CHECKLIST = [
  'TypeScript strict mode validation passed',
  'Dependency vulnerability scan completed',
  'React performance metrics within acceptable range',
  'Build environment integrity verified against baseline',
] as const;

export function isSecurityCompliant(policy: SecurityPolicy): boolean {
  return (
    policy.enableTypeScriptValidation &&
    policy.validateDependencies &&
    policy.checkPerformance &&
    policy.verifyBuildIntegrity
  );
}

/**
 * Returns a list of failing policy checks for diagnostic output.
 * Useful for surfacing which gates are blocking deployment.
 */
export function getFailingChecks(policy: SecurityPolicy): string[] {
  const failing: string[] = [];
  if (!policy.enableTypeScriptValidation) failing.push('TypeScript validation');
  if (!policy.validateDependencies)       failing.push('Dependency scan');
  if (!policy.checkPerformance)           failing.push('Performance check');
  if (!policy.verifyBuildIntegrity)       failing.push('Build integrity');
  return failing;
}
