/**
 * DLP Contextual Analysis Engine
 * Analyzes behavioral metrics, velocity, session anomalies, error bursts,
 * typing cadence, and maintains dynamic risk scores and user categorization.
 */

class ContextualEngine {
  constructor() {
    // In-memory user session contexts: userId/ip -> sessionState
    this.sessionContexts = new Map();
    // Sliding window duration: 60 seconds
    this.windowMs = 60000;
  }

  /**
   * Get or initialize session state for a user/IP
   */
  getSession(identifier) {
    if (!this.sessionContexts.has(identifier)) {
      this.sessionContexts.set(identifier, {
        id: identifier,
        requestHistory: [],
        violationHistory: [],
        errorCount: 0,
        consecutiveFails: 0,
        riskScore: 0,
        category: 'Benign',
        status: 'active', // 'active' | 'warned' | 'quarantined' | 'restricted' | 'blocked'
        honeypotActive: false,
        totalRequests: 0,
        keystrokeVariance: null,
        lastActive: Date.now()
      });
    }
    const session = this.sessionContexts.get(identifier);
    session.lastActive = Date.now();
    this.pruneHistory(session);
    return session;
  }

  /**
   * Remove requests older than the sliding window
   */
  pruneHistory(session) {
    const cutoff = Date.now() - this.windowMs;
    session.requestHistory = session.requestHistory.filter(t => t > cutoff);
  }

  /**
   * Evaluate contextual behavior for an incoming action
   * @param {string} identifier - User ID or IP
   * @param {object} actionContext - Action metadata (endpoint, method, payloadSize, typingSpeedMs, isError)
   * @param {object} contentReport - Output from ContentInspector
   */
  evaluateContext(identifier, actionContext = {}, contentReport = null) {
    const session = this.getSession(identifier);
    const now = Date.now();

    session.requestHistory.push(now);
    session.totalRequests += 1;

    const anomalies = [];
    let contextRiskDelta = 0;

    // 1. Velocity & Burst Rate Check (e.g. Automated Scanner / Scraping)
    const recentRequests = session.requestHistory.length;
    if (recentRequests > 15) {
      anomalies.push({
        type: 'VELOCITY_BURST',
        severity: 'HIGH',
        detail: `High query burst: ${recentRequests} requests in last 60s (potential automated scanner/assaulter).`,
        score: 30
      });
      contextRiskDelta += 30;
    } else if (recentRequests > 8) {
      anomalies.push({
        type: 'RAPID_REQUESTS',
        severity: 'MEDIUM',
        detail: `Elevated request frequency: ${recentRequests} requests in 60s.`,
        score: 15
      });
      contextRiskDelta += 15;
    }

    // 2. Error / Probing Anomaly Check (e.g. Fuzzing SQL syntax errors)
    if (actionContext.isError) {
      session.errorCount += 1;
      session.consecutiveFails += 1;
      if (session.consecutiveFails >= 3) {
        anomalies.push({
          type: 'CONSECUTIVE_ERRORS',
          severity: 'HIGH',
          detail: `Multiple failed database operations (${session.consecutiveFails} consecutive), typical of blind injection probing.`,
          score: 25
        });
        contextRiskDelta += 25;
      }
    } else {
      session.consecutiveFails = Math.max(0, session.consecutiveFails - 1);
    }

    // 3. Keystroke / Typing Cadence Anomaly (Theft / Script Paste Detection)
    // If typing speed is under 20ms for a complex 50+ character payload, it was automated or bot-pasted
    if (actionContext.typingSpeedMs && actionContext.payloadLength > 40) {
      const msPerChar = actionContext.typingSpeedMs / actionContext.payloadLength;
      if (msPerChar < 15) {
        anomalies.push({
          type: 'ANOMALOUS_KEYSTROKE_CADENCE',
          severity: 'MEDIUM',
          detail: `Sub-human typing interval (${msPerChar.toFixed(1)}ms/char). Indicates script automation or stolen replay payload.`,
          score: 20
        });
        contextRiskDelta += 20;
      }
    }

    // 4. Repeated Data Exfiltration Trajectory
    if (contentReport && contentReport.isThreat) {
      session.violationHistory.push({
        time: now,
        threatLevel: contentReport.threatLevel,
        matches: contentReport.matches.map(m => m.ruleId)
      });

      // Factor in content risk
      contextRiskDelta += contentReport.score;
    } else {
      // Natural decay for benign behavior
      if (session.riskScore > 0 && anomalies.length === 0) {
        session.riskScore = Math.max(0, session.riskScore - 2);
      }
    }

    // Update Accumulated Risk Score (bounded 0 - 100)
    session.riskScore = Math.min(100, Math.max(0, session.riskScore + contextRiskDelta));

    // Determine User Categorization
    const previousCategory = session.category;
    let newCategory = 'Benign';
    let intelligentAction = 'ALLOW';

    if (session.riskScore >= 70 || (contentReport && contentReport.threatLevel === 'CRITICAL')) {
      newCategory = 'Assaulter';
      session.status = 'restricted';
      session.honeypotActive = true;
      intelligentAction = 'RESTRICT_AND_HONEYPOT';
    } else if (session.riskScore >= 30 || anomalies.length > 0 || (contentReport && contentReport.isThreat)) {
      newCategory = 'Suspicious';
      session.status = 'warned';
      intelligentAction = 'WARN_AND_SANITIZE';
    } else {
      newCategory = 'Benign';
      if (session.status !== 'restricted' && session.status !== 'blocked') {
        session.status = 'active';
      }
      intelligentAction = 'ALLOW';
    }

    session.category = newCategory;

    return {
      userId: identifier,
      currentRiskScore: session.riskScore,
      previousCategory,
      newCategory,
      status: session.status,
      honeypotActive: session.honeypotActive,
      intelligentAction,
      anomalies,
      recentRequestsCount: session.requestHistory.length,
      totalViolations: session.violationHistory.length
    };
  }

  /**
   * Reset or modify user risk score manually (e.g. from SOC UI)
   */
  setUserStatus(identifier, status, riskScore = null) {
    const session = this.getSession(identifier);
    session.status = status;
    if (riskScore !== null) {
      session.riskScore = riskScore;
    } else if (status === 'active') {
      session.riskScore = 0;
      session.category = 'Benign';
      session.honeypotActive = false;
      session.consecutiveFails = 0;
    } else if (status === 'restricted' || status === 'blocked') {
      session.riskScore = 95;
      session.category = 'Assaulter';
      session.honeypotActive = true;
    }
    return session;
  }

  /**
   * Get all active sessions for SOC monitor
   */
  getAllSessions() {
    const list = [];
    for (const [id, session] of this.sessionContexts.entries()) {
      list.push({
        id,
        riskScore: session.riskScore,
        category: session.category,
        status: session.status,
        honeypotActive: session.honeypotActive,
        totalRequests: session.totalRequests,
        recentRequests: session.requestHistory.length,
        violationsCount: session.violationHistory.length,
        lastActive: session.lastActive
      });
    }
    return list;
  }
}

// Export singleton instance
module.exports = new ContextualEngine();
