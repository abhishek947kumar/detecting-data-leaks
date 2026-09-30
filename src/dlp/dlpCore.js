/**
 * DLP Core Orchestrator
 * Integrates Content Inspection, Contextual Behavioral Analysis,
 * Intelligent Restriction Actions, and SOC Telemetry Broadcasting.
 */

const { inspectContent, getActiveRules } = require('./contentInspector');
const contextualEngine = require('./contextualEngine');
const { logIncident, updateUserRisk, db } = require('../db/database');

// SSE Clients for real-time telemetry streaming
const sseClients = new Set();

function registerSseClient(res) {
  sseClients.add(res);
  res.on('close', () => {
    sseClients.delete(res);
  });
}

function broadcastTelemetry(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

/**
 * Main DLP Gateway Pipeline
 * @param {object} req - Express request
 * @param {string|object} payloadToInspect - The query or text to check
 * @param {string} contextSource - e.g. 'SQL_SEARCH', 'USER_CHAT', 'AUTH_LOGIN', 'CHECKOUT'
 * @param {object} additionalContext - Extra signals like typingSpeedMs, etc.
 */
function processDlpInspection(req, payloadToInspect, contextSource = 'GENERAL', additionalContext = {}) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userIdentifier = req.user ? req.user.username : (req.body && req.body.username ? req.body.username : `guest_${ip}`);
  const payloadStr = typeof payloadToInspect === 'object' ? JSON.stringify(payloadToInspect) : String(payloadToInspect || '');

  // Step 1: Content Inspection
  const contentReport = inspectContent(payloadStr, contextSource);

  // Step 2: Contextual Analysis
  const contextualReport = contextualEngine.evaluateContext(userIdentifier, {
    endpoint: req.originalUrl || req.path,
    method: req.method,
    payloadLength: payloadStr.length,
    typingSpeedMs: additionalContext.typingSpeedMs || null,
    isError: additionalContext.isError || false
  }, contentReport);

  // Step 3: Determine Combined Action & Enforcement
  let finalAction = 'ALLOWED';
  let shouldBlock = false;
  let serveHoneytoken = false;

  if (contextualReport.status === 'blocked' || contextualReport.status === 'restricted') {
    finalAction = 'USER_RESTRICTED';
    shouldBlock = true;
    serveHoneytoken = contextualReport.honeypotActive;
  } else if (contentReport.recommendedAction === 'RESTRICT_USER') {
    finalAction = 'USER_RESTRICTED';
    shouldBlock = true;
    serveHoneytoken = true;
    contextualEngine.setUserStatus(userIdentifier, 'restricted', 90);
  } else if (contentReport.recommendedAction === 'QUARANTINE_OR_HONEYTOKEN') {
    finalAction = 'HONEYTOKEN_SERVED';
    serveHoneytoken = true;
    shouldBlock = true;
  } else if (contentReport.recommendedAction === 'SANITIZE_AND_WARN' || contextualReport.status === 'warned') {
    finalAction = 'SANITIZED_AND_WARNED';
  }

  // Sync user state in DB if this is a registered user
  if (req.user && req.user.id) {
    try {
      updateUserRisk(req.user.id, contextualReport.currentRiskScore, contextualReport.newCategory, contextualReport.status);
    } catch (e) {
      // Ignore guest or sync error
    }
  }

  // Step 4: Audit & Log Security Incident if any threat detected
  let incidentId = null;
  if (contentReport.isThreat || contextualReport.anomalies.length > 0) {
    const rulesMatched = contentReport.matches.map(m => m.ruleName).concat(contextualReport.anomalies.map(a => a.type)).join(', ');
    const highestThreat = contentReport.threatLevel !== 'CLEAN' ? contentReport.threatLevel : (contextualReport.anomalies.some(a => a.severity === 'HIGH') ? 'HIGH' : 'MEDIUM');

    incidentId = logIncident({
      userIdentifier,
      ipAddress: ip,
      endpoint: req.originalUrl || req.path,
      requestPayload: payloadStr.length > 300 ? payloadStr.substring(0, 297) + '...' : payloadStr,
      detectionLayer: contentReport.isThreat && contextualReport.anomalies.length > 0 ? 'Hybrid (Content + Contextual)' : (contentReport.isThreat ? 'Content Inspection' : 'Contextual Analysis'),
      ruleMatched: rulesMatched || 'Anomaly Threshold Exceeded',
      threatLevel: highestThreat,
      riskScoreDelta: contentReport.score,
      actionTaken: finalAction,
      details: JSON.stringify({
        contentMatches: contentReport.matches,
        contextAnomalies: contextualReport.anomalies,
        userCategory: contextualReport.newCategory,
        riskScore: contextualReport.currentRiskScore
      })
    });

    // Step 5: Broadcast Real-Time Alert to Connected SOC Dashboards
    broadcastTelemetry('incident', {
      id: incidentId,
      timestamp: new Date().toISOString(),
      userIdentifier,
      ipAddress: ip,
      endpoint: req.originalUrl || req.path,
      threatLevel: highestThreat,
      detectionLayer: contentReport.isThreat ? 'Content Inspection' : 'Contextual Analysis',
      ruleMatched: rulesMatched,
      actionTaken: finalAction,
      userCategory: contextualReport.newCategory,
      riskScore: contextualReport.currentRiskScore,
      payloadSnippet: payloadStr.length > 80 ? payloadStr.substring(0, 77) + '...' : payloadStr
    });
  }

  return {
    contentReport,
    contextualReport,
    finalAction,
    shouldBlock,
    serveHoneytoken,
    sanitizedPayload: contentReport.sanitized,
    incidentId
  };
}

module.exports = {
  processDlpInspection,
  registerSseClient,
  broadcastTelemetry,
  contextualEngine,
  inspectContent,
  getActiveRules
};
