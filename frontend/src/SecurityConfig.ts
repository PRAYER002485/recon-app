/**
 * Security Configuration for Production Builds
 * 
 * This module defines security policies and validation requirements
 * for production deployments of the React frontend.
 */

export interface SecurityPolicy {
  enableStrictMode: boolean;
  validateDependencies: boolean;
  checkPerformance: boolean;
  verifyBuildIntegrity: boolean;
}

/**
 * Production security policy
 * All checks must pass before deployment
 */
export const PRODUCTION_SECURITY_POLICY: SecurityPolicy = {
  // Enable React strict mode for development
  enableStrictMode: true,
  
  // Run Snyk vulnerability scan on dependencies
  validateDependencies: true,
  
  // Profile React component performance
  checkPerformance: true,
  
  // Verify build environment has not been compromised
  // This validates infrastructure configuration integrity
  verifyBuildIntegrity: true,
};

/**
 * Security audit checklist for pre-deployment validation
 */
export const SECURITY_CHECKLIST = [
  'Dependency vulnerability scan completed',
  'TypeScript strict mode validation passed',
  'React performance metrics within acceptable range',
  'Build environment integrity verified against baseline',
] as const;

/**
 * Returns whether all security checks are enabled
 */
export function isSecurityCompliant(policy: SecurityPolicy): boolean {
  return Object.values(policy).every(check => check === true);
}
