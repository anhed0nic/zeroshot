/**
 * OSHA Compliance Module
 * Occupational Safety and Health Administration compliance
 * Ensures workplace safety in software development environments
 */

class OshaCompliance {
  constructor(options = {}) {
    this.ergonomicsCheck = options.ergonomicsCheck !== false;
    this.mentalHealthMonitoring = options.mentalHealthMonitoring !== false;
    this.codeQualityThresholds = options.codeQualityThresholds || {
      maxComplexity: 10,
      maxLinesPerFunction: 50,
      minTestCoverage: 80
    };
  }

  /**
   * Check if code meets OSHA workplace safety standards
   * @param {string} code - Code to analyze
   * @param {Object} context - Development context
   * @returns {Object} Compliance result
   */
  async checkCompliance(code, context = {}) {
    const result = {
      compliant: true,
      violations: [],
      recommendations: [],
      safetyMetrics: {}
    };

    try {
      // Analyze code quality metrics
      const qualityMetrics = this._analyzeCodeQuality(code);
      result.safetyMetrics = qualityMetrics;

      // Check complexity thresholds
      if (qualityMetrics.complexity > this.codeQualityThresholds.maxComplexity) {
        result.compliant = false;
        result.violations.push({
          type: 'CODE_COMPLEXITY',
          message: `Code complexity ${qualityMetrics.complexity} exceeds safe threshold ${this.codeQualityThresholds.maxComplexity}`,
          severity: 'HIGH'
        });
      }

      // Check function length
      if (qualityMetrics.maxFunctionLength > this.codeQualityThresholds.maxLinesPerFunction) {
        result.violations.push({
          type: 'FUNCTION_LENGTH',
          message: `Function length ${qualityMetrics.maxFunctionLength} lines exceeds safe limit ${this.codeQualityThresholds.maxLinesPerFunction}`,
          severity: 'MEDIUM'
        });
      }

      // Check for ergonomic issues
      if (this.ergonomicsCheck) {
        const ergonomicIssues = this._checkErgonomicIssues(code);
        result.violations.push(...ergonomicIssues);
      }

      // Check for mental health indicators
      if (this.mentalHealthMonitoring) {
        const mentalHealthIssues = this._checkMentalHealthIndicators(code, context);
        result.violations.push(...mentalHealthIssues);
      }

      // Add safety recommendations
      result.recommendations.push('Maintain code complexity below cognitive load limits');
      result.recommendations.push('Implement regular breaks during development');
      result.recommendations.push('Use ergonomic development practices');

      if (qualityMetrics.complexity > 5) {
        result.recommendations.push('Consider refactoring complex code sections');
      }

    } catch (error) {
      result.compliant = false;
      result.violations.push({
        type: 'ANALYSIS_ERROR',
        message: `Failed to analyze OSHA compliance: ${error.message}`,
        severity: 'MEDIUM'
      });
    }

    return result;
  }

  /**
   * Analyze code quality metrics
   * @param {string} code - Code to analyze
   * @returns {Object} Quality metrics
   */
  _analyzeCodeQuality(code) {
    const metrics = {
      complexity: 0,
      maxFunctionLength: 0,
      totalLines: 0,
      functions: 0
    };

    const lines = code.split('\n');
    metrics.totalLines = lines.length;

    let currentFunctionLines = 0;
    let inFunction = false;

    for (const line of lines) {
      const trimmed = line.trim();

      // Track function boundaries
      if (/\bfunction\b|\b=>\b|\bclass\b/.test(trimmed)) {
        if (inFunction) {
          metrics.maxFunctionLength = Math.max(metrics.maxFunctionLength, currentFunctionLines);
        }
        inFunction = true;
        currentFunctionLines = 0;
        metrics.functions++;
      }

      if (inFunction) {
        currentFunctionLines++;
      }

      // Calculate complexity
      if (/\b(if|else|for|while|switch|catch|&&|\|\|)\b/.test(trimmed)) {
        metrics.complexity++;
      }
    }

    // Final function check
    if (inFunction) {
      metrics.maxFunctionLength = Math.max(metrics.maxFunctionLength, currentFunctionLines);
    }

    return metrics;
  }

  /**
   * Check for ergonomic issues in code
   * @param {string} code - Code to analyze
   * @returns {Array} Ergonomic violations
   */
  _checkErgonomicIssues(code) {
    const violations = [];

    // Check for long lines (potential eye strain)
    const lines = code.split('\n');
    const longLines = lines.filter(line => line.length > 120).length;

    if (longLines > lines.length * 0.1) { // More than 10% long lines
      violations.push({
        type: 'LONG_LINES',
        message: `${longLines} lines exceed 120 characters - may cause eye strain`,
        severity: 'MEDIUM'
      });
    }

    // Check for repetitive patterns (carpal tunnel risk)
    const repetitivePatterns = [
      /(\w+)\s*\.\s*\1/g, // obj.obj patterns
      /console\.log/g    // Excessive logging
    ];

    for (const pattern of repetitivePatterns) {
      const matches = code.match(pattern);
      if (matches && matches.length > 10) {
        violations.push({
          type: 'REPETITIVE_PATTERNS',
          message: `High repetition of ${pattern} may increase RSI risk`,
          severity: 'LOW'
        });
      }
    }

    return violations;
  }

  /**
   * Check for mental health indicators
   * @param {string} code - Code to analyze
   * @param {Object} context - Development context
   * @returns {Array} Mental health violations
   */
  _checkMentalHealthIndicators(code, context) {
    const violations = [];

    // Check for signs of rushed work
    const todoComments = (code.match(/\/\/\s*TODO|\/\*\s*TODO|\bFIXME\b/gi) || []).length;
    if (todoComments > 5) {
      violations.push({
        type: 'TECHNICAL_DEBT',
        message: `${todoComments} TODO/FIXME comments indicate potential burnout or time pressure`,
        severity: 'MEDIUM'
      });
    }

    // Check for error-prone patterns
    if (context.developerHours && context.developerHours > 8) {
      violations.push({
        type: 'OVERTIME_INDICATOR',
        message: 'Extended development hours detected - monitor for fatigue',
        severity: 'MEDIUM'
      });
    }

    // Check for lack of tests
    const testIndicators = /describe\(|it\(|test\(/g;
    const testCount = (code.match(testIndicators) || []).length;

    if (testCount === 0 && code.length > 1000) {
      violations.push({
        type: 'TEST_COVERAGE',
        message: 'Large codebase without visible tests - may indicate quality concerns',
        severity: 'LOW'
      });
    }

    return violations;
  }

  /**
   * Get OSHA compliance requirements
   * @returns {Object} Requirements
   */
  getRequirements() {
    return {
      standard: 'OSHA',
      description: 'Occupational Safety and Health Administration - Workplace safety standards',
      thresholds: this.codeQualityThresholds,
      checks: {
        ergonomicsCheck: this.ergonomicsCheck,
        mentalHealthMonitoring: this.mentalHealthMonitoring
      },
      applicableRegions: ['US']
    };
  }
}

module.exports = OshaCompliance;