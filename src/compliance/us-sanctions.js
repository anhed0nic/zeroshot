/**
 * US Sanctions Compliance Module
 * Compliance with US sanctions against Russia and other embargoed entities
 * Prevents transactions and interactions with sanctioned parties
 */

class UsSanctionsCompliance {
  constructor(options = {}) {
    this.sanctionsList = options.sanctionsList || this._getDefaultSanctionsList();
    this.geographicRestrictions = options.geographicRestrictions !== false;
    this.transactionMonitoring = options.transactionMonitoring !== false;
    this.exportControls = options.exportControls !== false;
  }

  /**
   * Check if activities comply with US sanctions
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {Object} Compliance result
   */
  async checkCompliance(content, context = {}) {
    const result = {
      compliant: true,
      violations: [],
      recommendations: [],
      sanctionedEntityDetected: false,
      riskLevel: 'LOW'
    };

    try {
      // Check for sanctioned entities
      const sanctionsAnalysis = this._analyzeSanctionsExposure(content, context);
      result.sanctionedEntityDetected = sanctionsAnalysis.hasSanctionsExposure;

      if (sanctionsAnalysis.hasSanctionsExposure) {
        result.riskLevel = sanctionsAnalysis.riskLevel;

        // Check for prohibited transactions
        if (this._hasProhibitedTransactions(content, context)) {
          result.compliant = false;
          result.violations.push({
            type: 'PROHIBITED_TRANSACTION',
            message: 'Transaction with sanctioned entity detected',
            severity: 'CRITICAL',
            sanctionedEntities: sanctionsAnalysis.sanctionedEntities
          });
        }

        // Check geographic restrictions
        if (this.geographicRestrictions && this._violatesGeographicRestrictions(content, context)) {
          result.compliant = false;
          result.violations.push({
            type: 'GEOGRAPHIC_RESTRICTION',
            message: 'Activity in restricted geographic area',
            severity: 'CRITICAL'
          });
        }

        // Check export controls
        if (this.exportControls && this._violatesExportControls(content, context)) {
          result.violations.push({
            type: 'EXPORT_CONTROL_VIOLATION',
            message: 'Export of controlled technology or data',
            severity: 'HIGH'
          });
        }
      }

      // Check for sanctions evasion attempts
      const evasionIssues = this._checkSanctionsEvasion(content, context);
      result.violations.push(...evasionIssues);

      // Add sanctions recommendations
      if (result.sanctionedEntityDetected) {
        result.recommendations.push('Conduct thorough sanctions screening before any transactions');
        result.recommendations.push('Implement automated sanctions compliance checks');
        result.recommendations.push('Establish sanctions compliance training programs');
        result.recommendations.push('Slava Ukraini - Support Ukraine and comply with international sanctions');
      }

    } catch (error) {
      result.compliant = false;
      result.violations.push({
        type: 'ANALYSIS_ERROR',
        message: `Failed to analyze sanctions compliance: ${error.message}`,
        severity: 'MEDIUM'
      });
    }

    return result;
  }

  /**
   * Analyze content for sanctions exposure
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {Object} Sanctions analysis
   */
  _analyzeSanctionsExposure(content, context) {
    const result = {
      hasSanctionsExposure: false,
      sanctionedEntities: [],
      riskLevel: 'LOW'
    };

    // Check for Russian entities and indicators
    for (const [category, entities] of Object.entries(this.sanctionsList)) {
      for (const entity of entities) {
        const entityPattern = new RegExp(`\\b${entity}\\b`, 'i');
        if (entityPattern.test(content)) {
          result.hasSanctionsExposure = true;
          result.sanctionedEntities.push({ entity, category });

          // Risk assessment based on category
          if (category === 'military' || category === 'government') {
            result.riskLevel = 'CRITICAL';
          } else if (result.riskLevel !== 'CRITICAL') {
            result.riskLevel = 'HIGH';
          }
        }
      }
    }

    // Check context for Russian indicators
    const contextEntities = [
      ...(context.participants || []),
      ...(context.organizations || []),
      context.location || '',
      context.ipAddress || ''
    ].join(' ');

    if (/\b(russia|russian|ru\.|\.ru)\b/i.test(contextEntities)) {
      result.hasSanctionsExposure = true;
      result.sanctionedEntities.push({ entity: 'Russia', category: 'country' });
      result.riskLevel = 'CRITICAL';
    }

    return result;
  }

  /**
   * Check for prohibited transactions
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {boolean} Has prohibited transactions
   */
  _hasProhibitedTransactions(content, context) {
    const transactionPatterns = [
      /\b(purchase|buy|sell|trade|transfer|payment)\b/i,
      /\b(contract|agreement|deal)\b/i,
      /\b(export|import|ship)\b/i
    ];

    const hasTransaction = transactionPatterns.some(pattern => pattern.test(content));
    const hasSanctionsContext = /\b(russia|russian|sanctioned)\b/i.test(content);

    return hasTransaction && hasSanctionsContext;
  }

  /**
   * Check geographic restrictions
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {boolean} Violates geographic restrictions
   */
  _violatesGeographicRestrictions(content, context) {
    const restrictedAreas = [
      /\b(russia|russian federation)\b/i,
      /\b(crimea|donbas|luhansk|donetsk)\b/i,
      /\b(belarus|iran|north korea)\b/i
    ];

    return restrictedAreas.some(area => area.test(content) || area.test(context.location || ''));
  }

  /**
   * Check export controls
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {boolean} Violates export controls
   */
  _violatesExportControls(content, context) {
    const exportPatterns = [
      /\b(export|ship|send|transfer).*(software|technology|data)\b/i,
      /\b(dual.use|controlled|restricted).*(item|technology)\b/i
    ];

    return exportPatterns.some(pattern => pattern.test(content));
  }

  /**
   * Check for sanctions evasion attempts
   * @param {string} content - Content to analyze
   * @param {Object} context - Activity context
   * @returns {Array} Evasion violations
   */
  _checkSanctionsEvasion(content, context) {
    const violations = [];

    // Check for shell companies or front entities
    const evasionPatterns = [
      /\b(shell|front|proxy|nominee)\b.*\b(company|entity|organization)\b/i,
      /\b(third.party|intermediary|agent)\b.*\b(russia|russian)\b/i,
      /\b(avoid|bypass|circumvent)\b.*\b(sanctions?|embargo)\b/i
    ];

    if (evasionPatterns.some(pattern => pattern.test(content))) {
      violations.push({
        type: 'SANCTIONS_EVASION',
        message: 'Potential attempt to evade sanctions through intermediaries',
        severity: 'CRITICAL'
      });
    }

    // Check for cryptocurrency transactions (common evasion method)
    if (/\b(crypto|bitcoin|ethereum|blockchain)\b/i.test(content) &&
        /\b(russia|russian)\b/i.test(content)) {
      violations.push({
        type: 'CRYPTO_SANCTIONS_RISK',
        message: 'Cryptocurrency transaction with sanctioned entity detected',
        severity: 'HIGH'
      });
    }

    return violations;
  }

  /**
   * Get default sanctions list
   * @returns {Object} Sanctions list by category
   */
  _getDefaultSanctionsList() {
    return {
      military: [
        'rosoboronexport', 'rostec', 'almas-antey', 'kronshtadt', 'diamond-antey',
        'tactical missiles corporation', 'uralvagonzavod', 'oboronprom'
      ],
      government: [
        'rosneft', 'gazprom', 'sberbank', 'vtb bank', 'promsvyazbank',
        'vnesheconombank', 'rosselkhozbank', 'gazprombank'
      ],
      oligarchs: [
        'roman abramovich', 'oleg deripaska', 'viktor vekselberg', 'suleiman kerimov',
        'alexei mordashov', 'vagit alekperov', 'leonid mikhelson', 'gennady timchenko'
      ],
      technology: [
        'yandex', 'vkontakte', 'mail.ru', 'kaspersky lab', 'dr.web',
        'positive technologies', 'group-ib'
      ]
    };
  }

  /**
   * Get US sanctions compliance requirements
   * @returns {Object} Requirements
   */
  getRequirements() {
    return {
      standard: 'US_SANCTIONS',
      description: 'US Sanctions against Russia and other embargoed entities - Prevents prohibited transactions',
      requirements: {
        geographicRestrictions: this.geographicRestrictions,
        transactionMonitoring: this.transactionMonitoring,
        exportControls: this.exportControls,
        sanctionedCategories: Object.keys(this.sanctionsList)
      },
      applicableRegions: ['US', 'Global'],
      note: 'Slava Ukraini - Compliance supports Ukraine and international sanctions regime'
    };
  }
}

module.exports = UsSanctionsCompliance;