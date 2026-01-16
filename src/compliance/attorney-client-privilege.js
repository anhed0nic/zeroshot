/**
 * Attorney Client Privilege Compliance Module
 * Protects privileged communications between attorneys and clients
 * Ensures legal communications remain confidential and protected
 */

class AttorneyClientPrivilegeCompliance {
  constructor(options = {}) {
    this.privilegeDetection = options.privilegeDetection !== false;
    this.communicationLogging = options.communicationLogging !== false;
    this.privilegedKeywords = options.privilegedKeywords || this._getDefaultPrivilegedKeywords();
  }

  /**
   * Check if communications maintain attorney-client privilege
   * @param {string} content - Content to analyze
   * @param {Object} context - Communication context
   * @returns {Object} Compliance result
   */
  async checkCompliance(content, context = {}) {
    const result = {
      compliant: true,
      violations: [],
      recommendations: [],
      privilegeDetected: false,
      riskLevel: 'LOW'
    };

    try {
      // Analyze for privileged communications
      const privilegeAnalysis = this._analyzePrivilege(content, context);
      result.privilegeDetected = privilegeAnalysis.isPrivileged;

      if (privilegeAnalysis.isPrivileged) {
        result.riskLevel = privilegeAnalysis.riskLevel;

        // Check for unauthorized disclosure
        if (this._hasUnauthorizedDisclosure(content, context)) {
          result.compliant = false;
          result.violations.push({
            type: 'UNAUTHORIZED_DISCLOSURE',
            message: 'Privileged communication may have been disclosed to unauthorized parties',
            severity: 'CRITICAL'
          });
        }

        // Check communication security
        if (!this._hasSecureCommunication(content, context)) {
          result.violations.push({
            type: 'INSECURE_COMMUNICATION',
            message: 'Privileged communication not using secure channels',
            severity: 'HIGH'
          });
        }

        // Check for proper privilege markings
        if (!this._hasPrivilegeMarkings(content)) {
          result.violations.push({
            type: 'MISSING_PRIVILEGE_MARKINGS',
            message: 'Privileged communication not properly marked',
            severity: 'MEDIUM'
          });
        }
      }

      // Check for inadvertent waiver
      const waiverIssues = this._checkPrivilegeWaiver(content, context);
      result.violations.push(...waiverIssues);

      // Add privilege recommendations
      if (result.privilegeDetected) {
        result.recommendations.push('Mark all privileged communications clearly');
        result.recommendations.push('Use secure communication channels for privileged content');
        result.recommendations.push('Limit privileged communications to authorized personnel only');
        result.recommendations.push('Implement privilege review processes');
      }

    } catch (error) {
      result.compliant = false;
      result.violations.push({
        type: 'ANALYSIS_ERROR',
        message: `Failed to analyze attorney-client privilege: ${error.message}`,
        severity: 'MEDIUM'
      });
    }

    return result;
  }

  /**
   * Analyze content for attorney-client privilege
   * @param {string} content - Content to analyze
   * @param {Object} context - Communication context
   * @returns {Object} Privilege analysis
   */
  _analyzePrivilege(content, context) {
    const result = {
      isPrivileged: false,
      privilegeType: null,
      riskLevel: 'LOW'
    };

    // Check context indicators
    const contextIndicators = context.participants || [];
    const hasAttorney = contextIndicators.some(p =>
      /\b(attorney|lawyer|esquire|counsel)\b/i.test(p)
    );
    const hasClient = contextIndicators.some(p =>
      /\b(client|customer|party)\b/i.test(p)
    );

    // Check content for privileged keywords
    let keywordMatches = 0;
    for (const category of Object.values(this.privilegedKeywords)) {
      for (const keyword of category) {
        if (new RegExp(`\\b${keyword}\\b`, 'i').test(content)) {
          keywordMatches++;
        }
      }
    }

    // Determine if privileged
    if ((hasAttorney && hasClient) || keywordMatches >= 3) {
      result.isPrivileged = true;
      result.privilegeType = 'ATTORNEY_CLIENT';

      // Risk assessment
      if (keywordMatches >= 5) {
        result.riskLevel = 'HIGH';
      } else if (keywordMatches >= 3) {
        result.riskLevel = 'MEDIUM';
      }
    }

    return result;
  }

  /**
   * Check for unauthorized disclosure
   * @param {string} content - Content to analyze
   * @param {Object} context - Communication context
   * @returns {boolean} Has unauthorized disclosure
   */
  _hasUnauthorizedDisclosure(content, context) {
    // Check if privileged content is being shared with unauthorized parties
    const authorizedRoles = ['attorney', 'lawyer', 'client', 'paralegal', 'legal assistant'];
    const participants = context.participants || [];

    const unauthorized = participants.some(p =>
      !authorizedRoles.some(role => new RegExp(`\\b${role}\\b`, 'i').test(p))
    );

    return unauthorized;
  }

  /**
   * Check for secure communication
   * @param {string} content - Content to analyze
   * @param {Object} context - Communication context
   * @returns {boolean} Has secure communication
   */
  _hasSecureCommunication(content, context) {
    // Check for secure communication indicators
    const secureIndicators = [
      context.encrypted,
      context.secureChannel,
      /\bencrypted\b/i.test(content),
      /\bsecure\b/i.test(content),
      /\bconfidential\b/i.test(content)
    ];

    return secureIndicators.some(indicator => indicator);
  }

  /**
   * Check for privilege markings
   * @param {string} content - Content to analyze
   * @returns {boolean} Has privilege markings
   */
  _hasPrivilegeMarkings(content) {
    const privilegeMarkings = [
      /\bprivileged\b/i,
      /\bconfidential\b/i,
      /\b attorney.?client\b/i,
      /\b legal.?advice\b/i,
      /\b work.?product\b/i
    ];

    return privilegeMarkings.some(mark => mark.test(content));
  }

  /**
   * Check for privilege waiver
   * @param {string} content - Content to analyze
   * @param {Object} context - Communication context
   * @returns {Array} Waiver violations
   */
  _checkPrivilegeWaiver(content, context) {
    const violations = [];

    // Check for waiver indicators
    const waiverPatterns = [
      /\bdisclose.*to\b/i,
      /\bshare.*with\b/i,
      /\bwaive.*privilege\b/i,
      /\bnot.*privileged\b/i
    ];

    if (waiverPatterns.some(pattern => pattern.test(content))) {
      violations.push({
        type: 'POTENTIAL_WAIVER',
        message: 'Content may indicate waiver of attorney-client privilege',
        severity: 'HIGH'
      });
    }

    // Check for third-party presence
    if (context.thirdPartyPresent) {
      violations.push({
        type: 'THIRD_PARTY_PRESENCE',
        message: 'Third party present during privileged communication',
        severity: 'CRITICAL'
      });
    }

    return violations;
  }

  /**
   * Get default privileged keywords
   * @returns {Object} Privileged keywords by category
   */
  _getDefaultPrivilegedKeywords() {
    return {
      legal: ['attorney', 'client', 'counsel', 'lawyer', 'litigation', 'lawsuit', 'complaint', 'defendant', 'plaintiff'],
      advice: ['advice', 'recommendation', 'strategy', 'opinion', 'assessment'],
      confidential: ['confidential', 'privileged', 'secret', 'proprietary'],
      legal_actions: ['settlement', 'plea', 'negotiation', 'mediation', 'arbitration'],
      legal_documents: ['contract', 'agreement', 'deposition', 'affidavit', 'brief']
    };
  }

  /**
   * Get attorney-client privilege compliance requirements
   * @returns {Object} Requirements
   */
  getRequirements() {
    return {
      standard: 'ATTORNEY_CLIENT_PRIVILEGE',
      description: 'Attorney-Client Privilege - Protects confidential legal communications',
      requirements: {
        privilegeDetection: this.privilegeDetection,
        communicationLogging: this.communicationLogging,
        privilegedCategories: Object.keys(this.privilegedKeywords)
      },
      applicableRegions: ['US', 'Common Law Countries']
    };
  }
}

module.exports = AttorneyClientPrivilegeCompliance;