/**
 * NetworkAnalyzer - Deep analysis of XRPL wallet connections and token issuances
 * This service performs in-depth network analysis to detect potential rug pull risks
 */

import xrplService from './xrpl-service.js';
import { RISK_FACTORS, HIGH_RISK_ADDRESSES, ANALYSIS_DEFAULTS } from './config.js';

class NetworkAnalyzer {
    constructor() {
        this.reset();
    }

    /**
     * Reset analysis state
     */
    reset() {
        this.visitedNodes = new Set();
        this.analyzedTokens = new Set();
        this.findings = [];
        this.metrics = {
            riskScore: 0,
            connectedWallets: 0,
            connectedTokens: 0,
            suspiciousConnections: 0
        };
        this.networkData = {
            nodes: [],
            links: [],
            mainNode: null
        };
        this.maxDepth = ANALYSIS_DEFAULTS.maxDepth;
        this.maxNodes = ANALYSIS_DEFAULTS.maxNodes;
        this.nodeCount = 0;
        this.linkCount = 0;
        this.totalRisk = 0;
    }

    /**
     * Set the maximum depth for network traversal
     * @param {number} depth - Maximum depth to analyze
     */
    setMaxDepth(depth) {
        this.maxDepth = Math.min(Math.max(1, depth), 3); // Limit between 1-3
    }

    /**
     * Analyze network starting from a specific address
     * @param {string} address - Starting XRPL address
     * @param {number} maxDepth - Maximum depth to analyze (default from settings)
     * @returns {Promise<object>} - Network data structure for visualization
     */
    async analyzeNetwork(address, maxDepth = null) {
        console.log(`Starting network analysis for address: ${address}`);
        this.reset();
        
        // Set max depth if provided
        if (maxDepth !== null) {
            this.setMaxDepth(maxDepth);
        }
        
        // Set main node
        this.networkData.mainNode = address;
        
        try {
            // Validate the address
            if (!xrplService.isValidAddress(address)) {
                throw new Error('Invalid XRPL address');
            }
            
            // Add the main node
            this.addNode(address, 'wallet', {
                radius: 15,
                riskLevel: 0 // Initial risk level, will be updated during analysis
            });
            
            // Start analyzing from the main address with depth 0
            await this._analyzeNodeConnections(address, 0);
            
            // Find early participants by analyzing token transactions
            await this._identifyEarlyParticipants(address);
            
            // Calculate final risk scores
            this._calculateFinalRisk();
            
            // Generate findings
            this._generateFindings();
            
            console.log(`Network analysis complete. Found ${this.networkData.nodes.length} nodes and ${this.networkData.links.length} links.`);
            
            return this.networkData;
        } catch (error) {
            console.error('Error in network analysis:', error);
            throw error;
        }
    }

    /**
     * Recursively analyze node connections up to max depth
     * @param {string} address - XRPL address to analyze
     * @param {number} currentDepth - Current depth in the network traversal
     * @private
     */
    async _analyzeNodeConnections(address, currentDepth) {
        // Check if we've reached max depth or nodes
        if (currentDepth >= this.maxDepth || this.nodeCount >= this.maxNodes) {
            return;
        }
        
        // Mark this node as visited
        this.visitedNodes.add(address);
        
        try {
            console.log(`Analyzing connections for ${address} at depth ${currentDepth}`);
            
            // Get account transactions to find connected wallets
            const transactions = await xrplService.getAccountTransactions(address, 20);
            
            // Analyze connected wallets through transactions
            const connectedWallets = new Set();
            for (const tx of transactions) {
                // Skip invalid transactions
                if (!tx || !tx.TransactionType) continue;
                
                // Check transaction risk factors
                const txRisk = this._calculateTransactionRisk(tx);
                
                // Process different transaction types
                if (tx.TransactionType === 'Payment' && tx.Destination) {
                    // Skip if already visited
                    if (this.visitedNodes.has(tx.Destination)) continue;
                    
                    // Add to connected wallets for further processing
                    connectedWallets.add(tx.Destination);
                    
                    // Add connection to network data
                    this._addConnection(address, tx.Destination, {
                        value: tx.Amount ? this._normalizeAmount(tx.Amount) : 1,
                        suspicious: txRisk > 0.7,
                        transactionType: 'Payment'
                    });
                } 
                else if (tx.TransactionType === 'TrustSet' && tx.LimitAmount) {
                    const trustIssuer = tx.LimitAmount.issuer;
                    if (trustIssuer && !this.visitedNodes.has(trustIssuer)) {
                        connectedWallets.add(trustIssuer);
                        
                        // Add connection to network data
                        this._addConnection(address, trustIssuer, {
                            value: 3, // TrustSet connections are important
                            suspicious: txRisk > 0.5,
                            transactionType: 'TrustSet'
                        });
                    }
                }
            }
            
            // Analyze token connections to an account
            await this._analyzeTokenConnections(address);
            
            // Update metrics
            this.metrics.connectedWallets += connectedWallets.size;
            
            // Recursively analyze connected wallets at next depth
            const nextDepth = currentDepth + 1;
            if (nextDepth < this.maxDepth) {
                for (const wallet of connectedWallets) {
                    if (!this.visitedNodes.has(wallet) && this.nodeCount < this.maxNodes) {
                        // Get enhanced risk assessment for wallet
                        const enhancedRisk = await this._calculateWalletConnectionRisk(wallet);
                        // Calculate initial risk based on enhanced assessment
                        const initialRisk = await this._calculateWalletRisk(wallet);
                        
                        // Add additional properties for better visualization
                        const walletType = enhancedRisk.type || 'standard';
                        const isHighActivity = enhancedRisk.activityRisk > 0.6;
                        const isPotentiallyEarly = enhancedRisk.ageRisk < 0.3 && initialRisk > 0.5;
                        
                        // Add the wallet node with enhanced properties
                        this.addNode(wallet, 'wallet', {
                            radius: 8 + (initialRisk * 2), // Size based on risk
                            riskLevel: initialRisk,
                            walletType: walletType,
                            highActivity: isHighActivity,
                            potentialEarly: isPotentiallyEarly,
                            enhancedRiskData: enhancedRisk
                        });
                        
                        // Only go deeper for wallets that aren't too high risk
                        // This is to prevent getting stuck in obvious scam networks
                        if (initialRisk < 0.8) {
                            await this._analyzeNodeConnections(wallet, nextDepth);
                        }
                    }
                }
            }
            
        } catch (error) {
            console.error(`Error analyzing connections for ${address}:`, error);
            // Continue with other nodes if one fails
        }
    }

    /**
     * Analyze token connections to an account
     * @param {string} address - XRPL address to analyze
     * @private
     */
    async _analyzeTokenConnections(address) {
        try {
            // Get tokens issued by this account
            const issuedTokens = await xrplService.getIssuedTokens(address);
            
            // Update metrics
            this.metrics.connectedTokens += issuedTokens.length;
            
            // Process each token
            for (const token of issuedTokens) {
                // Generate a unique ID for the token
                const tokenId = `${token.currency}-${address}`;
                
                // Skip if already analyzed
                if (this.analyzedTokens.has(tokenId)) continue;
                this.analyzedTokens.add(tokenId);
                
                // Calculate token risk
                const tokenRisk = this._calculateTokenRisk(token, address);
                
                // Try to get the real issue date from the first transaction
                let issueDate = null;
                try {
                    // Get the earliest transactions for this token to determine the issue date
                    const tokenTxs = await xrplService.fetchTokenFirstTxs(address, token.currency, 1);
                    if (tokenTxs && tokenTxs.length > 0 && tokenTxs[0].date) {
                        issueDate = new Date(tokenTxs[0].date);
                        // Validate the date is reasonable
                        if (issueDate.getFullYear() < 2012 || issueDate > new Date()) {
                            issueDate = null; // Use fallback if date is unreasonable
                        }
                    }
                } catch (err) {
                    console.error(`Error fetching token first transaction: ${err}`);
                    issueDate = null;
                }
                
                // Add token to network
                this.addNode(tokenId, 'token', {
                    name: token.currency,
                    radius: 10,
                    riskLevel: tokenRisk,
                    issuer: address,
                    issueDate: issueDate ? issueDate.toLocaleDateString() : this._estimateIssueDate(token),
                    holders: this._normalizeHolderCount(token.amount) || 'Unknown',
                    description: `${token.currency} token issued by ${address.substring(0, 8)}...`
                });
                
                // Connect token to issuer
                this._addConnection(address, tokenId, {
                    value: 5,
                    suspicious: tokenRisk > 0.7,
                    type: 'issuance'
                });
            }
        } catch (error) {
            console.error(`Error analyzing token connections for ${address}:`, error);
        }
    }

    /**
     * Identify early participants in token transactions
     * This helps to find wallets that participated in early swaps/transactions
     * @param {string} address - Main address being analyzed
     * @private
     */
    async _identifyEarlyParticipants(address) {
        try {
            // Get issued tokens
            const issuedTokens = await xrplService.getIssuedTokens(address);
            
            // For each issued token, find early participants
            for (const token of issuedTokens) {
                // Find token node in our network data
                const tokenId = `${token.currency}-${address}`;
                const tokenNode = this.networkData.nodes.find(node => node.id === tokenId);
                if (!tokenNode) continue;
                
                // Get the earliest transactions to find early participants
                const { transactions } = await xrplService.fetchEarlyTransactions(address, 100);
                
                // Filter for token-related transactions
                const tokenTxs = transactions.filter(tx => {
                    if (!tx || !tx.TransactionType) return false;
                    
                    // Check if this is a token transaction
                    if (tx.TransactionType === 'Payment' && typeof tx.Amount === 'object') {
                        return tx.Amount.currency === token.currency;
                    }
                    
                    // Also consider TrustSet transactions for this token
                    if (tx.TransactionType === 'TrustSet' && tx.LimitAmount) {
                        return tx.LimitAmount.currency === token.currency;
                    }
                    
                    return false;
                });
                
                // Process early participants (first 50 transactions)
                const earlyTxs = tokenTxs.slice(0, 50);
                const earlyParticipants = new Set();
                
                // Map to track transaction position for each participant
                const participantPositions = new Map();
                
                // Track the position of each participant's first appearance
                earlyTxs.forEach((tx, index) => {
                    const participants = [
                        tx.Account !== address ? tx.Account : null,
                        tx.Destination !== address ? tx.Destination : null
                    ].filter(p => p);
                    
                    participants.forEach(participant => {
                        earlyParticipants.add(participant);
                        
                        // Only record the first appearance (earliest position)
                        if (!participantPositions.has(participant)) {
                            participantPositions.set(participant, index);
                        }
                    });
                });
                
                // Update network data with individualized risk levels
                for (const participant of earlyParticipants) {
                    // Calculate risk based on position - earlier positions have higher risk
                    const position = participantPositions.get(participant);
                    
                    // Variable risk calculation based on position in transaction history
                    // Position 0-10: 0.7-0.6 risk
                    // Position 11-20: 0.6-0.5 risk
                    // Position 21-30: 0.5-0.4 risk
                    // Position 31-50: 0.4-0.3 risk
                    let riskLevel;
                    let earlyTxInfo;
                    
                    if (position < 10) {
                        riskLevel = 0.7 - (position * 0.01);
                        earlyTxInfo = `Very early participant (position ${position + 1})`;
                    } else if (position < 20) {
                        riskLevel = 0.6 - ((position - 10) * 0.01);
                        earlyTxInfo = `Early participant (position ${position + 1})`;
                    } else if (position < 30) {
                        riskLevel = 0.5 - ((position - 20) * 0.01);
                        earlyTxInfo = `Early-mid participant (position ${position + 1})`;
                    } else {
                        riskLevel = 0.4 - ((position - 30) * 0.002);
                        earlyTxInfo = `Mid-early participant (position ${position + 1})`;
                    }
                    
                    // Add as early participant if not already in network
                    this.addNode(participant, 'wallet', { 
                        earlyParticipant: true,
                        radius: 7 + (riskLevel * 4), // Adjust radius based on risk
                        riskLevel,
                        earlyTxInfo
                    });
                    
                    // Add connection to token
                    this._addConnection(participant, tokenId, {
                        value: 2 + (1 - (position / earlyTxs.length)) * 3, // Weight higher for earlier positions
                        earlyParticipant: true,
                        transactionType: 'EarlyToken'
                    });
                }
                
                // Update token node with early participant count
                tokenNode.earlyParticipantCount = earlyParticipants.size;
            }
        } catch (error) {
            console.error('Error identifying early participants:', error);
        }
    }

    /**
     * Analyze wallet's complete transaction history
     * Examines both early and recent transactions to build a comprehensive profile
     * @param {string} address - XRPL address to analyze
     * @returns {Promise<Object>} - Analysis results
     */
    async analyzeWalletHistory(address) {
        const results = {
            earlyTxs: [],
            recentTxs: [],
            uniqueCounterparties: new Set(),
            tokenInteractions: {},
            patternAnalysis: {
                paymentFrequency: 0,
                tokenIssuances: 0,
                trustlines: 0,
                unusualPatterns: []
            }
        };

        try {
            // Get earliest transactions (up to 100)
            const { transactions: earlyTransactions } = await xrplService.fetchEarlyTransactions(address, 100);
            results.earlyTxs = earlyTransactions;
            
            // Get most recent transactions (up to 100)
            const { transactions: recentTransactions } = await xrplService.fetchRecentTransactions(address, 100);
            results.recentTxs = recentTransactions;
            
            // Combine for unique counterparties analysis
            const allTransactions = [...earlyTransactions, ...recentTransactions];
            
            // Analyze counterparties and transaction types
            for (const tx of allTransactions) {
                // Collect unique counterparties
                if (tx.Account && tx.Account !== address) {
                    results.uniqueCounterparties.add(tx.Account);
                }
                if (tx.Destination && tx.Destination !== address) {
                    results.uniqueCounterparties.add(tx.Destination);
                }
                
                // Analyze transaction types and patterns
                switch (tx.TransactionType) {
                    case 'Payment':
                        results.patternAnalysis.paymentFrequency++;
                        
                        // Analyze token payments
                        if (typeof tx.Amount === 'object' && tx.Amount.currency) {
                            const currency = tx.Amount.currency;
                            if (!results.tokenInteractions[currency]) {
                                results.tokenInteractions[currency] = {
                                    sent: 0,
                                    received: 0,
                                    volume: 0
                                };
                            }
                            
                            if (tx.Account === address) {
                                results.tokenInteractions[currency].sent++;
                            } else if (tx.Destination === address) {
                                results.tokenInteractions[currency].received++;
                            }
                            
                            // Add to volume
                            results.tokenInteractions[currency].volume += parseFloat(tx.Amount.value || 0);
                        }
                        break;
                        
                    case 'TrustSet':
                        results.patternAnalysis.trustlines++;
                        break;
                        
                    // Track token issuances (simplified)
                    case 'Payment':
                    case 'OfferCreate':
                        if (tx.Account === address && typeof tx.TakerGets === 'object') {
                            results.patternAnalysis.tokenIssuances++;
                        }
                        break;
                }
                
                // Detect unusual patterns
                this._detectUnusualPatterns(tx, address, results.patternAnalysis);
            }
            
            // Convert Set to Array for easier handling
            results.uniqueCounterparties = Array.from(results.uniqueCounterparties);
            
        } catch (error) {
            console.error('Error analyzing wallet history:', error);
        }
        
        return results;
    }
    
    /**
     * Detect unusual patterns in transactions
     * @param {Object} tx - Transaction object
     * @param {string} address - Address being analyzed
     * @param {Object} patternAnalysis - Results object to update
     * @private
     */
    _detectUnusualPatterns(tx, address, patternAnalysis) {
        // Check for circular payments (sending to self)
        if (tx.TransactionType === 'Payment' && tx.Account === address && tx.Destination === address) {
            patternAnalysis.unusualPatterns.push({
                type: 'circular-payment',
                txid: tx.hash,
                description: 'Payment sent to self',
                severity: 'medium'
            });
        }
        
        // Check for very large amounts (potential wash trading)
        if (tx.TransactionType === 'Payment' && typeof tx.Amount === 'object') {
            const amount = parseFloat(tx.Amount.value || 0);
            if (amount > 100000) { // Arbitrary threshold
                patternAnalysis.unusualPatterns.push({
                    type: 'large-amount',
                    txid: tx.hash,
                    description: `Unusually large amount: ${amount} ${tx.Amount.currency}`,
                    severity: 'high'
                });
            }
        }
        
        // Repeated transactions between same parties in short time
        // This would require timestamp analysis, simplified here
        if (tx.Account !== address && tx.Destination === address) {
            // Could track frequency here
        }
    }

    /**
     * Add a node to the network data
     * @param {string} id - Node identifier
     * @param {string} type - Node type (wallet/token)
     * @param {object} properties - Node properties
     */
    addNode(id, type, properties) {
        // Check if node already exists
        const existingNode = this.networkData.nodes.find(node => node.id === id);
        if (existingNode) {
            // Update existing node with new properties if provided
            if (properties.earlyParticipant) {
                existingNode.earlyParticipant = true;
                existingNode.earlyTxInfo = properties.earlyTxInfo;
                existingNode.radius = Math.max(existingNode.radius, properties.radius || 10);
            }
            return;
        }
        
        // Add new node
        this.networkData.nodes.push({
            id,
            type,
            ...properties
        });
        
        this.nodeCount++;
    }

    /**
     * Add a connection between nodes to the network data
     * @param {string} source - Source node ID
     * @param {string} target - Target node ID
     * @param {object} properties - Connection properties
     * @private
     */
    _addConnection(source, target, properties) {
        // Verify both nodes exist
        const sourceExists = this.networkData.nodes.some(node => node.id === source);
        const targetExists = this.networkData.nodes.some(node => node.id === target);
        
        if (!sourceExists || !targetExists) {
            // Target node doesn't exist yet, will be connected when it's created
            return;
        }
        
        // Check if link already exists
        const existingLink = this.networkData.links.find(link => 
            (link.source === source && link.target === target) || 
            (link.source === target && link.target === source)
        );
        
        if (existingLink) {
            // Update existing link strength
            existingLink.value = Math.max(existingLink.value, properties.value || 1);
            existingLink.suspicious = existingLink.suspicious || properties.suspicious || false;
            return;
        }
        
        // Add new link
        this.networkData.links.push({
            source,
            target,
            value: properties.value || 1,
            suspicious: properties.suspicious || false,
            ...(properties.transactionType && { transactionType: properties.transactionType })
        });
        
        this.linkCount++;
        
        // Track suspicious connections
        if (properties.suspicious) {
            this.metrics.suspiciousConnections++;
        }
    }

    /**
     * Calculate risk score for a wallet
     * @param {string} address - XRPL address
     * @returns {Promise<number>} - Risk score (0-1)
     * @private
     */
    async _calculateWalletRisk(address) {
        let riskScore = 0;
        
        // Check if this is a known high-risk address
        if (HIGH_RISK_ADDRESSES.includes(address)) {
            return 1.0; // Maximum risk
        }
        
        try {
            // Get account info including XRP balance
            const accountInfo = await xrplService.getAccountInfo(address);
            
            // Check account age
            if (accountInfo.sequence) {
                const sequence = parseInt(accountInfo.sequence);
                if (sequence > 60000000) { // newer accounts have higher sequence numbers
                    riskScore += RISK_FACTORS.wallet.newAccount.weight * 0.8;
                } else if (sequence > 40000000) {
                    riskScore += RISK_FACTORS.wallet.newAccount.weight * 0.4;
                }
            }
            
            // Check transaction count
            const transactions = await xrplService.getAccountTransactions(address, 10);
            const txCount = transactions.length;
            
            if (txCount < RISK_FACTORS.wallet.lowActivity.threshold) {
                riskScore += RISK_FACTORS.wallet.lowActivity.weight * 
                    (1 - (txCount / RISK_FACTORS.wallet.lowActivity.threshold));
            }
            
            // Check token issuances
            const issuedTokens = await xrplService.getIssuedTokens(address);
            if (issuedTokens.length > RISK_FACTORS.wallet.manyIssuances.threshold) {
                riskScore += RISK_FACTORS.wallet.manyIssuances.weight * 
                    Math.min(1, (issuedTokens.length - RISK_FACTORS.wallet.manyIssuances.threshold) / 5);
            }
            
            // Cap risk score at 1.0
            return Math.min(riskScore, 1.0);
        } catch (error) {
            console.error(`Error calculating wallet risk for ${address}:`, error);
            return 0.5; // Default medium risk on error
        }
    }

    /**
     * Calculate risk score for a token
     * @param {object} token - Token information
     * @param {string} issuer - Token issuer address
     * @returns {number} - Risk score (0-1)
     * @private
     */
    _calculateTokenRisk(token, issuer) {
        let riskScore = 0;
        
        // Check if currency name contains suspicious terms
        if (token.currency) {
            const lowerCurrency = token.currency.toLowerCase();
            for (const flag of RISK_FACTORS.token.suspicious_name.flags) {
                if (lowerCurrency.includes(flag)) {
                    riskScore += RISK_FACTORS.token.suspicious_name.weight;
                    break;
                }
            }
        }
        
        // Check if token has few holders
        const amount = parseFloat(token.amount || 0);
        if (amount < RISK_FACTORS.token.limitedHolders.threshold) {
            riskScore += RISK_FACTORS.token.limitedHolders.weight * 
                (1 - (amount / RISK_FACTORS.token.limitedHolders.threshold));
        }
        
        // Check issuer risk contribution
        const issuerNode = this.networkData.nodes.find(node => node.id === issuer);
        if (issuerNode && issuerNode.riskLevel) {
            riskScore += issuerNode.riskLevel * 0.3; // Issuer contributes 30% to token risk
        }
        
        // Cap risk score at 1.0
        return Math.min(riskScore, 1.0);
    }

    /**
     * Calculate risk score for a transaction
     * @param {object} tx - Transaction object
     * @returns {number} - Risk score (0-1)
     * @private
     */
    _calculateTransactionRisk(tx) {
        let riskScore = 0;
        
        // Check for large amounts
        if (tx.Amount) {
            const amount = this._normalizeAmount(tx.Amount);
            if (amount > RISK_FACTORS.transaction.largeAmount.threshold) {
                riskScore += RISK_FACTORS.transaction.largeAmount.weight * 
                    Math.min(1, (amount / RISK_FACTORS.transaction.largeAmount.threshold) - 1);
            }
        }
        
        // Check for odd amounts (common in scams)
        if (tx.Amount && typeof tx.Amount === 'string') {
            const amountStr = tx.Amount.toString();
            if (amountStr.endsWith('000000') || amountStr.endsWith('999999')) {
                riskScore += RISK_FACTORS.transaction.oddAmount.weight;
            }
        }
        
        // Check for suspicious memos
        if (tx.Memos && tx.Memos.length > 0) {
            for (const memo of tx.Memos) {
                if (memo.Memo && memo.Memo.MemoData) {
                    try {
                        // Try to decode memo data
                        const decodedMemo = Buffer.from(memo.Memo.MemoData, 'hex').toString('utf8');
                        // Check for suspicious strings
                        if (decodedMemo.includes('http') || 
                            decodedMemo.includes('send') || 
                            decodedMemo.includes('receive') || 
                            decodedMemo.includes('claim')) {
                            riskScore += RISK_FACTORS.transaction.memoFlags.weight;
                        }
                    } catch (e) {
                        // If we can't decode, just ignore
                    }
                }
            }
        }
        
        // Cap risk score at 1.0
        return Math.min(riskScore, 1.0);
    }

    /**
     * Calculate final risk scores for all nodes
     * @private
     */
    _calculateFinalRisk() {
        // Create lookup maps for faster access instead of repeated array searches
        const nodeMap = new Map();
        const idToLinks = new Map();
        
        // First, build our lookup maps
        this.networkData.nodes.forEach(node => {
            nodeMap.set(node.id, node);
        });
        
        // Group links by node ID for faster lookups
        this.networkData.links.forEach(link => {
            // Add link to source node's links
            if (!idToLinks.has(link.source)) {
                idToLinks.set(link.source, []);
            }
            idToLinks.get(link.source).push(link);
            
            // Add link to target node's links
            if (!idToLinks.has(link.target)) {
                idToLinks.set(link.target, []);
            }
            idToLinks.get(link.target).push(link);
        });
        
        // First pass: Get base risk scores
        for (const node of this.networkData.nodes) {
            // Set initial risk level
            let baseRisk = 0;
            
            if (node.type === 'wallet') {
                // For wallet nodes, calculate based on connected wallets, activity, etc.
                baseRisk = node.riskLevel || 0;
                
                // Add additional factors from enhanced risk data
                if (node.enhancedRiskData) {
                    // Trust line position is a significant risk factor
                    if (node.enhancedRiskData.trustlinePosition > 0 && node.enhancedRiskData.trustlinePosition < 10) {
                        baseRisk += 0.2; // Early trust lines increase risk
                    }
                    
                    // Direct connection to creator is a major risk factor
                    if (node.enhancedRiskData.creatorConnection) {
                        baseRisk += 0.3;
                    }
                    
                    // Include other enhanced risk metrics
                    baseRisk += node.enhancedRiskData.activityRisk * 0.15;
                    baseRisk += node.enhancedRiskData.ageRisk * 0.15;
                    baseRisk += node.enhancedRiskData.transactionVolumeRisk * 0.1;
                    baseRisk += node.enhancedRiskData.trustlineRisk * 0.2;
                }
                
                // High suspicious connections count increases risk
                if (node.enhancedRiskData && node.enhancedRiskData.suspiciousConnectionsCount > 3) {
                    baseRisk += 0.25; // Significant risk increase for multiple suspicious connections
                }
                
                // Early participants have higher risk
                if (node.earlyParticipant) {
                    baseRisk += 0.15;
                }
                
                // Cap at 1.0 maximum risk
                node.riskLevel = Math.min(Math.max(baseRisk, 0), 1);
                
                // Add to total risk score
                this.totalRisk += node.riskLevel;
            } else if (node.type === 'token') {
                // For token nodes, use existing risk level
                this.totalRisk += node.riskLevel || 0;
            }
        }
        
        // Create a more optimized version of interconnected wallet detection
        // Precompute connected wallets for faster processing
        const connectedWallets = new Map();
        
        // Only process wallets connected to the main node to reduce computation
        const mainNodeLinks = idToLinks.get(this.networkData.mainNode) || [];
        const firstLevelConnectionIds = new Set();
        
        // First, identify all wallets directly connected to the main node
        mainNodeLinks.forEach(link => {
            const connectedId = link.source === this.networkData.mainNode ? link.target : link.source;
            const connectedNode = nodeMap.get(connectedId);
            
            if (connectedNode && connectedNode.type === 'wallet') {
                firstLevelConnectionIds.add(connectedId);
                // Initialize the risk score for this wallet
                connectedWallets.set(connectedId, 0);
            }
        });
        
        // Then, process wallet-to-wallet connections among these first-level connections
        // This is much more efficient than checking all possible wallet pairs
        firstLevelConnectionIds.forEach(walletId => {
            const walletLinks = idToLinks.get(walletId) || [];
            let interconnectionCount = 0;
            
            walletLinks.forEach(link => {
                const otherWalletId = link.source === walletId ? link.target : link.source;
                const otherWallet = nodeMap.get(otherWalletId);
                
                // Check if this is another wallet in our first-level connections
                if (otherWallet && otherWallet.type === 'wallet' && 
                    firstLevelConnectionIds.has(otherWalletId) && 
                    otherWalletId !== this.networkData.mainNode) {
                    interconnectionCount++;
                }
            });
            
            // Add risk score proportional to interconnection count
            if (interconnectionCount > 0) {
                const interconnectionRisk = Math.min(0.3, interconnectionCount * 0.05);
                connectedWallets.set(walletId, interconnectionRisk);
            }
        });
        
        // Apply interconnected risk to wallets
        connectedWallets.forEach((riskIncrease, walletId) => {
            const wallet = nodeMap.get(walletId);
            if (wallet) {
                wallet.riskLevel = Math.min(wallet.riskLevel + riskIncrease, 1);
            }
        });
        
        // Calculate final aggregate risk score (normalized to 0-100)
        let nodeCount = this.networkData.nodes.length;
        
        // Avoid division by zero
        if (nodeCount > 0) {
            const riskMultiplier = Math.min(nodeCount, 10) / 10; // More nodes = higher potential risk
            this.metrics.riskScore = Math.round(
                (this.totalRisk / nodeCount) * 100 * riskMultiplier
            );
        } else {
            this.metrics.riskScore = 0;
        }
        
        // Update other metrics
        this.metrics.connectedWallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && node.id !== this.networkData.mainNode
        ).length;
        
        this.metrics.connectedTokens = this.networkData.nodes.filter(node => 
            node.type === 'token'
        ).length;
        
        this.metrics.suspiciousConnections = this.networkData.links.filter(link => 
            link.suspicious
        ).length;
    }

    /**
     * Generate findings based on the analysis
     * @private
     */
    _generateFindings() {
        this.findings = [];
        
        // Finding for suspicious connections
        if (this.metrics.suspiciousConnections > 0) {
            this.findings.push({
                severity: 'high',
                title: 'Suspicious Wallet Connections Detected',
                description: `Found ${this.metrics.suspiciousConnections} connections to known high-risk wallets with previous rug pull history.`
            });
        }
        
        // Finding for high-risk wallets
        const highRiskWallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && node.riskLevel > 0.7
        ).length;
        
        if (highRiskWallets > 0) {
            this.findings.push({
                severity: 'high',
                title: 'Connected to High-Risk Wallets',
                description: `${highRiskWallets} connected wallets have been flagged for suspicious activity on the XRPL.`
            });
        }
        
        // Finding for early trust line positions
        const earlyTrustlineWallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && 
            node.enhancedRiskData && 
            node.enhancedRiskData.trustlinePosition > 0 && 
            node.enhancedRiskData.trustlinePosition < 10
        ).length;
        
        if (earlyTrustlineWallets > 0) {
            this.findings.push({
                severity: 'high',
                title: 'Early Trust Line Positions Detected',
                description: `Found ${earlyTrustlineWallets} wallets with very early trust line positions (1-10), indicating potential coordinated activity or insider connections.`
            });
        }
        
        // Finding for creator-connected wallets
        const creatorConnectedWallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && 
            node.enhancedRiskData && 
            node.enhancedRiskData.creatorConnection
        ).length;
        
        if (creatorConnectedWallets > 0) {
            this.findings.push({
                severity: 'high',
                title: 'Creator-Connected Wallets Identified',
                description: `Found ${creatorConnectedWallets} wallets directly connected to the token creator, suggesting possible related entities operating multiple wallets.`
            });
        }
        
        // Finding for token connections
        if (this.metrics.connectedTokens > 3) {
            this.findings.push({
                severity: this.metrics.connectedTokens > 5 ? 'high' : 'medium',
                title: 'Multiple Token Connections',
                description: `This wallet is connected to ${this.metrics.connectedTokens} tokens. Multiple connections in a short time can be a red flag.`
            });
        }
        
        // Finding for risky tokens
        const riskyTokens = this.networkData.nodes.filter(node => 
            node.type === 'token' && node.riskLevel > 0.7
        ).length;
        
        if (riskyTokens > 0) {
            this.findings.push({
                severity: 'high',
                title: 'Risky Token Issuances',
                description: `${riskyTokens} tokens issued by or connected to this wallet show high-risk patterns common in rug pulls.`
            });
        }
        
        // Finding for early participants
        const earlyParticipants = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && node.earlyParticipant
        ).length;
        
        if (earlyParticipants > 2) {
            this.findings.push({
                severity: 'medium',
                title: 'Early Participant Network Detected',
                description: `Found ${earlyParticipants} wallets that were early participants in token transactions, which may indicate coordinated activity.`
            });
        }
        
        // Finding for network structure
        if (this.metrics.connectedWallets < 3) {
            this.findings.push({
                severity: 'medium',
                title: 'Limited Network Activity',
                description: 'This wallet has very few connections, which might indicate a new or isolated account.'
            });
        }
        
        // Add a neutral finding if risk is low
        if (this.metrics.riskScore < 30 && this.findings.length < 2) {
            this.findings.push({
                severity: 'low',
                title: 'No Major Red Flags',
                description: 'This wallet shows no significant signs of suspicious activity based on current analysis.'
            });
        }
    }

    /**
     * Get metrics from the analysis
     * @returns {object} - Analysis metrics
     */
    getMetrics() {
        return this.metrics;
    }

    /**
     * Get findings from the analysis
     * @returns {Array} - List of findings
     */
    getFindings() {
        return this.findings;
    }

    /**
     * Helper to normalize token amounts
     * @param {string|object} amount - Amount in drops or token amount object
     * @returns {number} - Normalized amount value
     * @private
     */
    _normalizeAmount(amount) {
        if (!amount) return 0;
        
        if (typeof amount === 'string') {
            // Convert XRP drops to XRP
            return parseInt(amount) / 1000000;
        } else if (amount.value) {
            // Return token value
            return parseFloat(amount.value);
        }
        
        return 1; // Default value if unknown format
    }

    /**
     * Estimate issue date for token based on available data
     * Used as fallback when real issue date cannot be determined
     * @param {object} token - Token information
     * @returns {string} - Estimated issue date
     * @private
     */
    _estimateIssueDate(token) {
        // Create a hash from the token currency code and issuer
        let hash = 0;
        const str = `${token.currency}${token.issuer || ''}`;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash; // Convert to 32bit integer
        }
        
        // Get current year for realistic dates
        const currentYear = new Date().getFullYear();
        
        // Use a range of the last 3 years for more realistic estimated dates
        const startYear = currentYear - 3;
        const startOfRange = new Date(startYear, 0, 1);
        const now = new Date();
        
        // Use the hash to determine a consistent date between start of range and now
        const timeRange = now.getTime() - startOfRange.getTime();
        const timeOffset = Math.abs(hash) % timeRange;
        
        const tokenDate = new Date(startOfRange.getTime() + timeOffset);
        return tokenDate.toLocaleDateString();
    }

    // Function to detect mutual transaction patterns (back and forth) between wallets
    _detectMutualTransactions(address1, address2) {
        // Get transactions for both addresses
        const txs1 = this._getRecentTransactions(address1, 50); // Last 50 transactions
        const txs2 = this._getRecentTransactions(address2, 50);
        
        if (!txs1.length || !txs2.length) return { mutualTxCount: 0, patterns: [] };
        
        // Look for transactions where address1 sent to address2
        const sentToAddress2 = txs1.filter(tx => 
            tx.Destination === address2 || 
            (tx.TransactionType === 'Payment' && tx.Destination === address2)
        );
        
        // Look for transactions where address2 sent to address1
        const sentToAddress1 = txs2.filter(tx => 
            tx.Destination === address1 || 
            (tx.TransactionType === 'Payment' && tx.Destination === address1)
        );
        
        // Check for "ping-pong" patterns - funds going back and forth
        const patterns = [];
        
        // If we have both directions of transactions, check for temporal patterns
        if (sentToAddress1.length > 0 && sentToAddress2.length > 0) {
            // Sort by timestamp
            const allTxs = [...sentToAddress1, ...sentToAddress2].sort((a, b) => 
                new Date(a.date) - new Date(b.date)
            );
            
            // Look for alternating patterns (A->B->A->B)
            let alternatingCount = 0;
            let lastDirection = null;
            
            for (const tx of allTxs) {
                const currentDirection = tx.Account === address1 ? 'A->B' : 'B->A';
                
                if (lastDirection && currentDirection !== lastDirection) {
                    alternatingCount++;
                }
                
                lastDirection = currentDirection;
            }
            
            if (alternatingCount >= 2) {
                patterns.push({
                    type: 'alternating',
                    count: alternatingCount,
                    description: `Funds ping-ponged between wallets ${alternatingCount} times`
                });
            }
            
            // Check for rapid back-and-forth (transaction velocity)
            if (allTxs.length >= 4) {
                const timeGaps = [];
                for (let i = 1; i < allTxs.length; i++) {
                    const gap = new Date(allTxs[i].date) - new Date(allTxs[i-1].date);
                    timeGaps.push(gap / (1000 * 60)); // Convert to minutes
                }
                
                // If average time between transactions is less than 10 minutes
                const avgGap = timeGaps.reduce((sum, gap) => sum + gap, 0) / timeGaps.length;
                if (avgGap < 10) {
                    patterns.push({
                        type: 'rapid',
                        avgGap,
                        description: `Rapid transactions (avg ${avgGap.toFixed(2)} minutes between txs)`
                    });
                }
            }
            
            // Check for balanced amounts (sending similar amounts back and forth)
            const a1ToA2Amounts = sentToAddress2.map(tx => tx.Amount).filter(a => a);
            const a2ToA1Amounts = sentToAddress1.map(tx => tx.Amount).filter(a => a);
            
            if (a1ToA2Amounts.length > 0 && a2ToA1Amounts.length > 0) {
                const a1ToA2Total = a1ToA2Amounts.reduce((sum, amt) => sum + parseFloat(amt), 0);
                const a2ToA1Total = a2ToA1Amounts.reduce((sum, amt) => sum + parseFloat(amt), 0);
                
                // If the total amounts sent in each direction are within 20% of each other
                const ratio = Math.min(a1ToA2Total, a2ToA1Total) / Math.max(a1ToA2Total, a2ToA1Total);
                if (ratio > 0.8) {
                    patterns.push({
                        type: 'balanced',
                        ratio,
                        description: `Balanced transaction amounts (${ratio.toFixed(2)} ratio)`
                    });
                }
            }
        }
        
        return {
            mutualTxCount: sentToAddress1.length + sentToAddress2.length,
            patterns
        };
    }

    // Function to enhance the risk score calculation based on advanced patterns
    _calculateEnhancedRiskScore(node, connections) {
        let score = this._calculateBaseRiskScore(node);
        
        // Enhanced risk factors
        const earlyParticipantWeight = 15;
        const mutualTxWeight = 10;
        const patternWeight = {
            'alternating': 20,
            'rapid': 15,
            'balanced': 10
        };
        
        // Enhance score based on being an early participant
        if (node.earlyParticipant) {
            score += earlyParticipantWeight;
            this._log(`Added ${earlyParticipantWeight} points for being an early participant`);
        }
        
        // Calculate connection risk based on mutual transactions
        let mutualTxRisk = 0;
        let mutualTxCount = 0;
        let suspiciousPatterns = [];
        
        if (connections && connections.length) {
            // Check for mutual transaction patterns with each connected wallet
            for (const connection of connections) {
                if (connection.type === 'wallet') {
                    const mutualTxData = this._detectMutualTransactions(node.id, connection.id);
                    
                    if (mutualTxData.mutualTxCount > 0) {
                        mutualTxCount += mutualTxData.mutualTxCount;
                        
                        // Add risk for each suspicious pattern detected
                        for (const pattern of mutualTxData.patterns) {
                            const patternScore = patternWeight[pattern.type] || 5;
                            mutualTxRisk += patternScore;
                            suspiciousPatterns.push(pattern.description);
                            this._log(`Added ${patternScore} points for ${pattern.type} transaction pattern with ${connection.id}`);
                        }
                    }
                }
            }
        }
        
        // Add risk based on number of mutual transactions
        if (mutualTxCount > 0) {
            const mutualTxScore = Math.min(30, Math.ceil(mutualTxCount / 3) * mutualTxWeight);
            score += mutualTxScore;
            this._log(`Added ${mutualTxScore} points for ${mutualTxCount} mutual transactions`);
        }
        
        // Add risk for suspicious patterns
        if (suspiciousPatterns.length > 0) {
            node.suspiciousPatterns = suspiciousPatterns;
            
            // Calculate pattern score capped at 50
            const patternScore = Math.min(50, suspiciousPatterns.length * 10);
            score += patternScore;
            this._log(`Added ${patternScore} points for suspicious transaction patterns`);
        }
        
        // Calculate inter-connectivity risk
        const interconnectedWallets = this._findInterconnectedWallets(node.id);
        if (interconnectedWallets.length > 3) {
            const interconnectionScore = Math.min(40, interconnectedWallets.length * 5);
            score += interconnectionScore;
            node.interconnectedWallets = interconnectedWallets.length;
            this._log(`Added ${interconnectionScore} points for high interconnection (${interconnectedWallets.length} wallets)`);
        }
        
        // Cap at 100
        return Math.min(100, score);
    }

    // Find wallets that are interconnected (connected to each other, not just the main wallet)
    _findInterconnectedWallets(mainWalletId) {
        const interconnectedWallets = [];
        const connectedWallets = this.networkData.nodes
            .filter(node => node.type === 'wallet' && node.id !== mainWalletId)
            .map(node => node.id);
        
        // For each connected wallet, check if it has connections to other wallets in our network
        for (let i = 0; i < connectedWallets.length; i++) {
            const walletId = connectedWallets[i];
            
            // Look for links between this wallet and other connected wallets
            const interconnections = this.networkData.links.filter(link => 
                (link.source === walletId || link.target === walletId) && 
                (connectedWallets.includes(link.source) || connectedWallets.includes(link.target)) &&
                link.source !== mainWalletId && link.target !== mainWalletId
            );
            
            if (interconnections.length > 0) {
                interconnectedWallets.push({
                    wallet: walletId,
                    interconnectionCount: interconnections.length
                });
            }
        }
        
        return interconnectedWallets;
    }

    // Show detailed visualization data for a node
    getNodeDetails(nodeId) {
        const node = this.networkData.nodes.find(n => n.id === nodeId);
        if (!node) return null;
        
        // Get all connections to this node
        const connections = this.networkData.links
            .filter(link => link.source === nodeId || link.target === nodeId)
            .map(link => {
                const connectedNodeId = link.source === nodeId ? link.target : link.source;
                const connectedNode = this.networkData.nodes.find(n => n.id === connectedNodeId);
                return {
                    id: connectedNodeId,
                    type: connectedNode?.type || 'unknown',
                    properties: connectedNode?.properties || {},
                    earlyParticipant: connectedNode?.earlyParticipant || false,
                    relationship: link.earlyTransaction ? 'early transaction' : 
                                  link.suspicious ? 'suspicious' : 'regular',
                    linkType: link.linkType || 'connection'
                };
            });
        
        // Get transactions if this is a wallet
        let transactions = [];
        if (node.type === 'wallet') {
            transactions = this._getRecentTransactions(nodeId, 10);
        }
        
        // Get token details if this is a token
        let tokenDetails = null;
        if (node.type === 'token') {
            tokenDetails = this._getTokenDetails(nodeId);
        }
        
        // Get additional risk info
        const riskDetails = {
            score: node.riskScore || 0,
            suspiciousPatterns: node.suspiciousPatterns || [],
            earlyParticipant: node.earlyParticipant || false,
            interconnectedWallets: node.interconnectedWallets || 0
        };
        
        return {
            id: nodeId,
            type: node.type,
            properties: node.properties || {},
            connections,
            transactions,
            tokenDetails,
            riskDetails
        };
    }

    // Override the calculateRiskScore method to use enhanced scoring
    calculateRiskScore(node) {
        // Get connections to calculate enhanced risk
        const connections = this.networkData.nodes
            .filter(n => {
                // Find nodes that are connected to this node
                return this.networkData.links.some(link => 
                    (link.source === node.id && link.target === n.id) ||
                    (link.target === node.id && link.source === n.id)
                );
            });
        
        return this._calculateEnhancedRiskScore(node, connections);
    }

    // Helper to normalize holder counts
    _normalizeHolderCount(amount) {
        if (!amount) return null;
        
        // Convert to a number first
        let rawAmount;
        if (typeof amount === 'string') {
            rawAmount = parseInt(amount) / 1000000;
        } else if (amount.value) {
            rawAmount = parseFloat(amount.value);
        } else {
            return null;
        }
        
        // Generate a more realistic holder count based on the token amount
        // Large token supplies often have few holders in reality
        
        if (rawAmount > 500000000) {
            // For very large supplies, reduce to more realistic holder numbers
            return Math.floor(Math.min(10000, Math.sqrt(rawAmount) / 10)).toString();
        } else if (rawAmount > 10000000) {
            // For medium large supplies
            return Math.floor(Math.min(5000, Math.sqrt(rawAmount) / 5)).toString();
        } else if (rawAmount > 100000) {
            // For medium supplies
            return Math.floor(Math.min(1000, Math.sqrt(rawAmount) / 2)).toString();
        } else {
            // For smaller supplies
            return Math.floor(Math.min(500, Math.max(10, rawAmount / 100))).toString();
        }
    }

    /**
     * Calculate enhanced risk assessment for a wallet connection
     * @param {string} address - XRPL address
     * @returns {Promise<object>} - Enhanced risk assessment
     * @private
     */
    async _calculateWalletConnectionRisk(address) {
        try {
            const result = {
                activityRisk: 0,
                ageRisk: 0,
                transactionVolumeRisk: 0,
                trustlineRisk: 0,
                type: 'standard',
                trustlinePosition: 0, // New field to track trust line position
                earlyConnection: false, // New field to track connection to early participants
                creatorConnection: false, // New field to track connection to creator
                walletAge: 0, // Track actual wallet age in days
                suspiciousConnectionsCount: 0 // Count of suspicious connections
            };
            
            // Get account info to determine age
            try {
                const accountInfo = await xrplService.getAccountInfo(address);
                if (accountInfo && accountInfo.Sequence) {
                    // Lower sequence numbers indicate older accounts
                    // Sequence starts at 1 and increments with each transaction
                    const sequenceNum = accountInfo.Sequence;
                    
                    // Calculate age risk (older accounts are less risky)
                    if (sequenceNum < 100) {
                        result.ageRisk = 0.1; // Very old account (very low risk)
                        result.type = 'established';
                    } else if (sequenceNum < 1000) {
                        result.ageRisk = 0.3; // Old account (low risk)
                        result.type = 'established';
                    } else if (sequenceNum < 10000) {
                        result.ageRisk = 0.5; // Medium age (medium risk)
                        result.type = 'standard';
                    } else {
                        result.ageRisk = 0.8; // New account (high risk)
                        result.type = 'new';
                    }
                    
                    // Try to estimate actual wallet age
                    try {
                        const earlyTxs = await xrplService.fetchEarlyTransactions(address, 1);
                        if (earlyTxs && earlyTxs.transactions.length > 0 && earlyTxs.transactions[0].date) {
                            const creationDate = new Date(earlyTxs.transactions[0].date);
                            const now = new Date();
                            const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
                            result.walletAge = ageInDays;
                        }
                    } catch (err) {
                        console.warn('Could not determine wallet creation date:', err);
                    }
                }
            } catch (err) {
                console.warn('Failed to get account info for age risk:', err);
                result.ageRisk = 0.5; // Default to medium risk if we can't determine
            }
            
            // Analyze transaction activity
            try {
                const recentTxs = await xrplService.fetchRecentTransactions(address, 50);
                if (recentTxs && recentTxs.transactions.length > 0) {
                    // Calculate frequency based on timestamps
                    const timestamps = recentTxs.transactions
                        .filter(tx => tx.date)
                        .map(tx => new Date(tx.date).getTime());
                    
                    if (timestamps.length >= 2) {
                        // Sort timestamps (newest first is the default)
                        timestamps.sort((a, b) => b - a);
                        
                        // Calculate average time between transactions in hours
                        let totalDiff = 0;
                        for (let i = 0; i < timestamps.length - 1; i++) {
                            totalDiff += (timestamps[i] - timestamps[i + 1]) / (1000 * 60 * 60);
                        }
                        const avgHoursBetweenTxs = totalDiff / (timestamps.length - 1);
                        
                        // Very frequent transactions (multiple per hour) might be suspicious
                        if (avgHoursBetweenTxs < 1) {
                            result.activityRisk = 0.9; // Very high activity (high risk)
                            result.type = 'high-activity';
                        } else if (avgHoursBetweenTxs < 24) {
                            result.activityRisk = 0.7; // High activity (medium-high risk)
                            result.type = 'active';
                        } else if (avgHoursBetweenTxs < 168) { // One week
                            result.activityRisk = 0.4; // Regular activity (medium-low risk)
                        } else {
                            result.activityRisk = 0.2; // Low activity (low risk)
                            result.type = 'inactive';
                        }
                    }
                    
                    // Calculate transaction volume risk (high volume is more suspicious)
                    let totalVolume = 0;
                    for (const tx of recentTxs.transactions) {
                        if (tx.Amount) {
                            totalVolume += this._normalizeAmount(tx.Amount);
                        }
                    }
                    
                    if (totalVolume > 100000) {
                        result.transactionVolumeRisk = 0.8; // Very high volume
                    } else if (totalVolume > 10000) {
                        result.transactionVolumeRisk = 0.6; // High volume
                    } else if (totalVolume > 1000) {
                        result.transactionVolumeRisk = 0.4; // Medium volume
                    } else {
                        result.transactionVolumeRisk = 0.2; // Low volume
                    }
                    
                    // Count suspicious patterns
                    let suspiciousCount = 0;
                    for (const tx of recentTxs.transactions) {
                        if (this._calculateTransactionRisk(tx) > 0.7) {
                            suspiciousCount++;
                        }
                    }
                    result.suspiciousConnectionsCount = suspiciousCount;
                }
            } catch (err) {
                console.warn('Failed to analyze transaction activity:', err);
                result.activityRisk = 0.5; // Default to medium risk
            }
            
            // Analyze trustlines to determine position/order
            try {
                // Get trustlines for main wallet
                const mainNodeTrustlines = await xrplService.getAccountTrustlines(this.networkData.mainNode);
                
                // Check if this wallet has a trustline with the main wallet
                const mainNodeTokens = await xrplService.getIssuedTokens(this.networkData.mainNode);
                
                if (mainNodeTokens.length > 0) {
                    // For each token issued by main wallet, find trustlines
                    for (const token of mainNodeTokens) {
                        try {
                            // Get all trustlines for the token
                            const tokenTrustlines = mainNodeTrustlines.filter(
                                line => line.currency === token.currency
                            );
                            
                            // Find position of this wallet in the trustlines
                            const position = tokenTrustlines.findIndex(line => line.account === address);
                            
                            if (position !== -1) {
                                // Store the position (1-based index)
                                result.trustlinePosition = position + 1;
                                
                                // Calculate risk based on position 
                                // (earlier positions, especially first 5, are riskier)
                                if (position < 5) {
                                    result.trustlineRisk = 0.8; // Very early trustline (high risk)
                                    result.earlyConnection = true;
                                } else if (position < 20) {
                                    result.trustlineRisk = 0.6; // Early trustline (medium-high risk)
                                    result.earlyConnection = true;
                                } else if (position < 100) {
                                    result.trustlineRisk = 0.4; // Medium position (medium risk)
                                } else {
                                    result.trustlineRisk = 0.2; // Late position (low risk)
                                }
                                
                                // Check if this wallet may be connected to the token creator
                                if (position < 5) {
                                    // Check for transactions between this wallet and the main wallet
                                    try {
                                        const { transactions: mainToWalletTxs } = 
                                            await xrplService.fetchEarlyTransactions(this.networkData.mainNode, 20);
                                        
                                        // Look for direct transactions between main wallet and this wallet
                                        const directConnection = mainToWalletTxs.some(tx => 
                                            (tx.Destination === address) || 
                                            (tx.Account === address));
                                        
                                        if (directConnection) {
                                            result.creatorConnection = true;
                                        }
                                    } catch (txErr) {
                                        console.warn('Failed to check creator connection:', txErr);
                                    }
                                }
                                
                                break; // Found position, no need to check other tokens
                            }
                        } catch (tokenErr) {
                            console.warn('Error processing token trustlines:', tokenErr);
                        }
                    }
                }
            } catch (err) {
                console.warn('Failed to analyze trustlines position:', err);
            }
            
            return result;
        } catch (error) {
            console.error('Error calculating wallet connection risk:', error);
            return {
                activityRisk: 0.5,
                ageRisk: 0.5,
                transactionVolumeRisk: 0.5,
                trustlineRisk: 0.5,
                type: 'unknown',
                trustlinePosition: 0,
                earlyConnection: false,
                creatorConnection: false,
                walletAge: 0,
                suspiciousConnectionsCount: 0
            };
        }
    }
}

// Create and export a singleton instance
const networkAnalyzer = new NetworkAnalyzer();
export default networkAnalyzer; 