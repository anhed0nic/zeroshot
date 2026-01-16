/**
 * HIPAA Compliance Module
 * Health Insurance Portability and Accountability Act compliance
 * Protects patient health information (PHI) in healthcare environments
 */

const crypto = require('crypto');

class HipaaCompliance {
  constructor(options = {}) {
    this.encryptionRequired = options.encryptionRequired !== false;
    this.auditLogging = options.auditLogging !== false;
    this.phiPatterns = options.phiPatterns || this._getDefaultPhiPatterns();
  }

  /**
   * Check if code handles PHI appropriately
   * @param {string} code - Code to analyze
   * @param {Object} context - Execution context
   * @returns {Object} Compliance result
   */
  async checkCompliance(code, context = {}) {
    const result = {
      compliant: true,
      violations: [],
      recommendations: [],
      phiDetected: false,
      riskLevel: 'LOW'
    };

    try {
      // Check for PHI patterns in code
      const phiAnalysis = this._analyzePhiPresence(code);
      result.phiDetected = phiAnalysis.hasPhi;

      if (phiAnalysis.hasPhi) {
        result.riskLevel = phiAnalysis.riskLevel;

        // Check encryption requirements
        if (this.encryptionRequired && !this._hasEncryption(code)) {
          result.compliant = false;
          result.violations.push({
            type: 'ENCRYPTION_MISSING',
            message: 'PHI detected but no encryption mechanisms found',
            severity: 'CRITICAL',
            phiTypes: phiAnalysis.phiTypes
          });
        }

        // Check for proper access controls
        if (!this._hasAccessControls(code)) {
          result.violations.push({
            type: 'ACCESS_CONTROL_MISSING',
            message: 'PHI handling without proper access controls',
            severity: 'HIGH'
          });
        }

        // Check audit logging
        if (this.auditLogging && !this._hasAuditLogging(code)) {
          result.violations.push({
            type: 'AUDIT_LOGGING_MISSING',
            message: 'PHI operations without audit logging',
            severity: 'HIGH'
          });
        }
      }

      // Check for insecure data handling
      const securityIssues = this._checkSecurityIssues(code);
      result.violations.push(...securityIssues);

      // Add recommendations
      if (result.phiDetected) {
        result.recommendations.push('Implement proper PHI encryption at rest and in transit');
        result.recommendations.push('Add role-based access controls for PHI data');
        result.recommendations.push('Enable audit logging for all PHI operations');
        result.recommendations.push('Implement data minimization principles');
      }

    } catch (error) {
      result.compliant = false;
      result.violations.push({
        type: 'ANALYSIS_ERROR',
        message: `Failed to analyze HIPAA compliance: ${error.message}`,
        severity: 'MEDIUM'
      });
    }

    return result;
  }

  /**
   * Analyze code for PHI presence
   * @param {string} code - Code to analyze
   * @returns {Object} PHI analysis result
   */
  _analyzePhiPresence(code) {
    const result = {
      hasPhi: false,
      phiTypes: [],
      riskLevel: 'LOW'
    };

    for (const [type, patterns] of Object.entries(this.phiPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(code)) {
          result.hasPhi = true;
          result.phiTypes.push(type);

          // Determine risk level
          if (['ssn', 'medicalRecord'].includes(type)) {
            result.riskLevel = 'CRITICAL';
          } else if (result.riskLevel !== 'CRITICAL') {
            result.riskLevel = 'HIGH';
          }
          break;
        }
      }
    }

    return result;
  }

  /**
   * Check for encryption mechanisms
   * @param {string} code - Code to analyze
   * @returns {boolean} Has encryption
   */
  _hasEncryption(code) {
    const encryptionPatterns = [
      /\bcrypto\./,
      /\bencrypt\b/i,
      /\bdecrypt\b/i,
      /\bcrypt\b/i,
      /\bhash\b/i,
      /\bssl\b/i,
      /\btls\b/i
    ];

    return encryptionPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check for access controls
   * @param {string} code - Code to analyze
   * @returns {boolean} Has access controls
   */
  _hasAccessControls(code) {
    const accessPatterns = [
      /\bauthenticate\b/i,
      /\bauthorize\b/i,
      /\bpermission\b/i,
      /\broles?\b/i,
      /\bacl\b/i,
      /\baccess.control\b/i
    ];

    return accessPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check for audit logging
   * @param {string} code - Code to analyze
   * @returns {boolean} Has audit logging
   */
  _hasAuditLogging(code) {
    const auditPatterns = [
      /\blog\b/i,
      /\baudit\b/i,
      /\btrack\b/i,
      /\brecord\b/i
    ];

    return auditPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check for security issues
   * @param {string} code - Code to analyze
   * @returns {Array} Security violations
   */
  _checkSecurityIssues(code) {
    const violations = [];

    // Check for hardcoded sensitive data
    if (/\b(password|secret|key)\s*[:=]\s*['"][^'"]{8,}['"]/.test(code)) {
      violations.push({
        type: 'HARDCODED_SECRETS',
        message: 'Potential hardcoded secrets detected',
        severity: 'CRITICAL'
      });
    }

    // Check for insecure data transmission
    if (/\bhttp:\s*\/\//.test(code) && !/\bhttps:/.test(code)) {
      violations.push({
        type: 'INSECURE_TRANSMISSION',
        message: 'HTTP used instead of HTTPS for data transmission',
        severity: 'HIGH'
      });
    }

    return violations;
  }

  /**
   * Get default PHI detection patterns
   * @returns {Object} PHI patterns
   */
  _getDefaultPhiPatterns() {
    return {
      ssn: [/\b\d{3}-\d{2}-\d{4}\b/, /\b\d{9}\b/],
      medicalRecord: [/\bpatient\b/i, /\bdiagnosis\b/i, /\btreatment\b/i],
      personalInfo: [/\bname\b/i, /\baddress\b/i, /\bphone\b/i, /\bemail\b/i],
      demographics: [/\bage\b/i, /\bgender\b/i, /\brace\b/i]
    };
  }

  /**
   * Get HIPAA compliance requirements
   * @returns {Object} Requirements
   */
  getRequirements() {
    return {
      standard: 'HIPAA',
      description: 'Health Insurance Portability and Accountability Act - Protects patient health information',
      requirements: {
        encryptionRequired: this.encryptionRequired,
        auditLogging: this.auditLogging,
        phiPatterns: Object.keys(this.phiPatterns)
      },
      applicableRegions: ['US']
    };
  }
}

module.exports = HipaaCompliance;