/**
 * GDPR Compliance Module
 * General Data Protection Regulation compliance
 * Protects personal data in the European Union
 */

class GdprCompliance {
  constructor(options = {}) {
    this.dataRetentionDays = options.dataRetentionDays || 2555; // ~7 years max
    this.consentRequired = options.consentRequired !== false;
    this.rightToErasure = options.rightToErasure !== false;
    this.personalDataPatterns = options.personalDataPatterns || this._getDefaultPersonalDataPatterns();
  }

  /**
   * Check if code meets GDPR requirements
   * @param {string} code - Code to analyze
   * @param {Object} context - Execution context
   * @returns {Object} Compliance result
   */
  async checkCompliance(code, context = {}) {
    const result = {
      compliant: true,
      violations: [],
      recommendations: [],
      personalDataDetected: false,
      riskLevel: 'LOW'
    };

    try {
      // Check for personal data handling
      const dataAnalysis = this._analyzePersonalData(code);
      result.personalDataDetected = dataAnalysis.hasPersonalData;

      if (dataAnalysis.hasPersonalData) {
        result.riskLevel = dataAnalysis.riskLevel;

        // Check consent mechanisms
        if (this.consentRequired && !this._hasConsentMechanism(code)) {
          result.compliant = false;
          result.violations.push({
            type: 'CONSENT_MISSING',
            message: 'Personal data processing without consent mechanism',
            severity: 'CRITICAL'
          });
        }

        // Check data retention policies
        if (!this._hasDataRetentionPolicy(code)) {
          result.violations.push({
            type: 'RETENTION_POLICY_MISSING',
            message: 'No data retention policy for personal data',
            severity: 'HIGH'
          });
        }

        // Check right to erasure
        if (this.rightToErasure && !this._hasRightToErasure(code)) {
          result.violations.push({
            type: 'RIGHT_TO_ERASURE_MISSING',
            message: 'No mechanism for data erasure requests',
            severity: 'HIGH'
          });
        }

        // Check data minimization
        if (!this._followsDataMinimization(code)) {
          result.violations.push({
            type: 'DATA_MINIMIZATION_VIOLATION',
            message: 'Code collects more data than necessary',
            severity: 'MEDIUM'
          });
        }
      }

      // Check for international data transfers
      const transferIssues = this._checkDataTransfers(code);
      result.violations.push(...transferIssues);

      // Add GDPR recommendations
      if (result.personalDataDetected) {
        result.recommendations.push('Implement explicit user consent mechanisms');
        result.recommendations.push('Establish data retention schedules');
        result.recommendations.push('Provide data erasure capabilities');
        result.recommendations.push('Conduct Data Protection Impact Assessment (DPIA)');
        result.recommendations.push('Appoint a Data Protection Officer (DPO)');
      }

    } catch (error) {
      result.compliant = false;
      result.violations.push({
        type: 'ANALYSIS_ERROR',
        message: `Failed to analyze GDPR compliance: ${error.message}`,
        severity: 'MEDIUM'
      });
    }

    return result;
  }

  /**
   * Analyze code for personal data handling
   * @param {string} code - Code to analyze
   * @returns {Object} Personal data analysis
   */
  _analyzePersonalData(code) {
    const result = {
      hasPersonalData: false,
      dataTypes: [],
      riskLevel: 'LOW'
    };

    for (const [type, patterns] of Object.entries(this.personalDataPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(code)) {
          result.hasPersonalData = true;
          result.dataTypes.push(type);

          // Determine risk level based on data sensitivity
          if (['genetic', 'biometric', 'racial'].includes(type)) {
            result.riskLevel = 'CRITICAL';
          } else if (['financial', 'health'].includes(type) && result.riskLevel !== 'CRITICAL') {
            result.riskLevel = 'HIGH';
          } else if (result.riskLevel === 'LOW') {
            result.riskLevel = 'MEDIUM';
          }
          break;
        }
      }
    }

    return result;
  }

  /**
   * Check for consent mechanisms
   * @param {string} code - Code to analyze
   * @returns {boolean} Has consent mechanism
   */
  _hasConsentMechanism(code) {
    const consentPatterns = [
      /\bconsent\b/i,
      /\bagree\b/i,
      /\bopt.?in\b/i,
      /\bpermission\b/i,
      /\bauthorization\b/i
    ];

    return consentPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check for data retention policies
   * @param {string} code - Code to analyze
   * @returns {boolean} Has retention policy
   */
  _hasDataRetentionPolicy(code) {
    const retentionPatterns = [
      /\bretention\b/i,
      /\bexpire\b/i,
      /\bdelete.*after\b/i,
      /\bttl\b/i,
      /\bcleanup\b/i
    ];

    return retentionPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check for right to erasure mechanisms
   * @param {string} code - Code to analyze
   * @returns {boolean} Has erasure mechanism
   */
  _hasRightToErasure(code) {
    const erasurePatterns = [
      /\berasure\b/i,
      /\bdelete.*user\b/i,
      /\bremove.*data\b/i,
      /\bgdpr.*delete\b/i
    ];

    return erasurePatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check if code follows data minimization
   * @param {string} code - Code to analyze
   * @returns {boolean} Follows minimization
   */
  _followsDataMinimization(code) {
    // Simple heuristic: check if code has selective data collection
    const collectionPatterns = /\bcollect.*only\b|\bminimal.*data\b|\bnecessary.*data\b/i;
    return collectionPatterns.test(code);
  }

  /**
   * Check for international data transfer issues
   * @param {string} code - Code to analyze
   * @returns {Array} Transfer violations
   */
  _checkDataTransfers(code) {
    const violations = [];

    // Check for data transfer to non-EU countries
    const transferPatterns = [
      /\bexport.*data\b/i,
      /\bsend.*to.*(us|china|russia|asia)\b/i,
      /\btransfer.*international\b/i
    ];

    if (transferPatterns.some(pattern => pattern.test(code))) {
      violations.push({
        type: 'INTERNATIONAL_TRANSFER',
        message: 'Potential international data transfer without adequacy check',
        severity: 'HIGH'
      });
    }

    return violations;
  }

  /**
   * Get default personal data patterns
   * @returns {Object} Personal data patterns
   */
  _getDefaultPersonalDataPatterns() {
    return {
      name: [/\bname\b/i, /\bfirstname\b/i, /\blastname\b/i],
      email: [/\bemail\b/i, /\bmail\b/i],
      phone: [/\bphone\b/i, /\bmobile\b/i, /\btelephone\b/i],
      address: [/\baddress\b/i, /\blocation\b/i, /\bcity\b/i, /\bcountry\b/i],
      financial: [/\bcredit.?card\b/i, /\bbank\b/i, /\baccount\b/i, /\biban\b/i],
      health: [/\bhealth\b/i, /\bmedical\b/i, /\bdiagnosis\b/i],
      genetic: [/\bdna\b/i, /\bgenetic\b/i],
      biometric: [/\bfingerprint\b/i, /\bface\b/i, /\bvoice\b/i],
      racial: [/\brace\b/i, /\bethnicity\b/i],
      religious: [/\breligion\b/i, /\bbelief\b/i],
      political: [/\bpolitical\b/i, /\bparty\b/i]
    };
  }

  /**
   * Get GDPR compliance requirements
   * @returns {Object} Requirements
   */
  getRequirements() {
    return {
      standard: 'GDPR',
      description: 'General Data Protection Regulation - EU data protection law',
      requirements: {
        dataRetentionDays: this.dataRetentionDays,
        consentRequired: this.consentRequired,
        rightToErasure: this.rightToErasure,
        personalDataTypes: Object.keys(this.personalDataPatterns)
      },
      applicableRegions: ['EU', 'EEA']
    };
  }
}

module.exports = GdprCompliance;