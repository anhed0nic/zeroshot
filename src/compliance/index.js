/**
 * Compliance Engine
 * Orchestrates regulatory compliance checks across multiple standards
 */

const CafeCompliance = require('./cafe');
const HipaaCompliance = require('./hipaa');
const OshaCompliance = require('./osha');
const GdprCompliance = require('./gdpr');
const AttorneyClientPrivilegeCompliance = require('./attorney-client-privilege');
const UsSanctionsCompliance = require('./us-sanctions');

class ComplianceEngine {
  constructor(options = {}) {
    this.complianceModules = {
      cafe: new CafeCompliance(options.cafe || {}),
      hipaa: new HipaaCompliance(options.hipaa || {}),
      osha: new OshaCompliance(options.osha || {}),
      gdpr: new GdprCompliance(options.gdpr || {}),
      attorneyClientPrivilege: new AttorneyClientPrivilegeCompliance(options.attorneyClientPrivilege || {}),
      usSanctions: new UsSanctionsCompliance(options.usSanctions || {})
    };

    this.enabledModules = options.enabledModules || Object.keys(this.complianceModules);
    this.failOnAnyViolation = options.failOnAnyViolation !== false;
  }

  /**
   * Run compliance checks on content
   * @param {string} content - Content to check
   * @param {Object} context - Context information
   * @returns {Object} Compliance results
   */
  async checkCompliance(content, context = {}) {
    const results = {
      overallCompliant: true,
      moduleResults: {},
      summary: {
        totalViolations: 0,
        criticalViolations: 0,
        highViolations: 0,
        recommendations: []
      }
    };

    // Run checks for enabled modules
    for (const moduleName of this.enabledModules) {
      if (this.complianceModules[moduleName]) {
        try {
          const moduleResult = await this.complianceModules[moduleName].checkCompliance(content, context);
          results.moduleResults[moduleName] = moduleResult;

          // Update overall compliance
          if (!moduleResult.compliant) {
            results.overallCompliant = false;
          }

          // Update summary
          results.summary.totalViolations += moduleResult.violations.length;
          results.summary.criticalViolations += moduleResult.violations.filter(v => v.severity === 'CRITICAL').length;
          results.summary.highViolations += moduleResult.violations.filter(v => v.severity === 'HIGH').length;
          results.summary.recommendations.push(...moduleResult.recommendations);

        } catch (error) {
          results.moduleResults[moduleName] = {
            compliant: false,
            violations: [{
              type: 'MODULE_ERROR',
              message: `Compliance module ${moduleName} failed: ${error.message}`,
              severity: 'HIGH'
            }],
            recommendations: []
          };
          results.overallCompliant = false;
        }
      }
    }

    // Remove duplicate recommendations
    results.summary.recommendations = [...new Set(results.summary.recommendations)];

    return results;
  }

  /**
   * Get compliance requirements for all enabled modules
   * @returns {Object} Requirements by module
   */
  getRequirements() {
    const requirements = {};

    for (const moduleName of this.enabledModules) {
      if (this.complianceModules[moduleName]) {
        requirements[moduleName] = this.complianceModules[moduleName].getRequirements();
      }
    }

    return requirements;
  }

  /**
   * Enable or disable specific compliance modules
   * @param {string} moduleName - Module to toggle
   * @param {boolean} enabled - Whether to enable
   */
  setModuleEnabled(moduleName, enabled) {
    if (enabled && !this.enabledModules.includes(moduleName)) {
      this.enabledModules.push(moduleName);
    } else if (!enabled) {
      this.enabledModules = this.enabledModules.filter(m => m !== moduleName);
    }
  }

  /**
   * Get list of available compliance modules
   * @returns {Array} Module names
   */
  getAvailableModules() {
    return Object.keys(this.complianceModules);
  }

  /**
   * Configure a specific compliance module
   * @param {string} moduleName - Module to configure
   * @param {Object} config - Configuration options
   */
  configureModule(moduleName, config) {
    if (this.complianceModules[moduleName]) {
      // Reinitialize module with new config
      const ModuleClass = this.complianceModules[moduleName].constructor;
      this.complianceModules[moduleName] = new ModuleClass(config);
    }
  }
}

module.exports = ComplianceEngine;