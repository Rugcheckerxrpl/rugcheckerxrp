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
        this.progress = {
            status: 'starting',
            percent: 0,
            message: 'Initializing analysis...',
            startTime: Date.now()
        };
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
        
        // Set up progress tracking
        this.progress = {
            status: 'starting',
            percent: 0,
            message: 'Initializing analysis...',
            startTime: Date.now()
        };
        
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
            
            // Update progress
            this._updateProgress(5, 'Validating address...');
            
            // Add the main node
            this.addNode(address, 'wallet', {
                radius: 15,
                riskLevel: 0 // Initial risk level, will be updated during analysis
            });
            
            // Update progress
            this._updateProgress(10, 'Starting connection analysis...');
            
            // Start analyzing from the main address with depth 0
            await this._analyzeNodeConnections(address, 0);
            
            // Update progress
            this._updateProgress(60, 'Analyzing token connections...');
            
            // Find early participants by analyzing token transactions
            await this._identifyEarlyParticipants(address);
            
            // Update progress
            this._updateProgress(80, 'Calculating risk scores...');
            
            // Calculate final risk scores
            this._calculateFinalRisk();
            
            // Update progress
            this._updateProgress(90, 'Generating findings...');
            
            // Generate findings - use setTimeout to prevent UI blocking
            await new Promise(resolve => {
                setTimeout(() => {
                    this._generateFindings();
                    resolve();
                }, 10);
            });
            
            // Update progress
            this._updateProgress(100, 'Analysis complete');
            
            console.log(`Network analysis complete. Found ${this.networkData.nodes.length} nodes and ${this.networkData.links.length} links.`);
            
            return this.networkData;
        } catch (error) {
            console.error('Error in network analysis:', error);
            this._updateProgress(100, `Error: ${error.message}`);
            throw error;
        }
    }
    
    /**
     * Update the progress of the analysis
     * @param {number} percent - Progress percentage (0-100)
     * @param {string} message - Progress message
     * @private
     */
    _updateProgress(percent, message) {
        this.progress = {
            status: percent < 100 ? 'in_progress' : 'complete',
            percent: Math.min(100, Math.max(0, percent)),
            message: message || '',
            elapsedMs: Date.now() - this.progress.startTime
        };
        
        // Dispatch a progress event that can be listened to by the UI
        if (typeof window !== 'undefined' && window.dispatchEvent) {
            const progressEvent = new CustomEvent('network-analysis-progress', { 
                detail: this.progress 
            });
            window.dispatchEvent(progressEvent);
        }
        
        console.log(`Progress: ${this.progress.percent}% - ${this.progress.message}`);
    }
    
    /**
     * Get current progress information
     * @returns {object} - Progress information
     */
    getProgress() {
        return this.progress;
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
            // Enhanced data collection for buying patterns
            const walletInteractions = new Map();
            
            // Check if this wallet is the creator of the main address
            let isCreatorWallet = false;
            if (currentDepth === 1) {
                try {
                    const mainAccountInfo = await xrplService.getAccountInfo(this.networkData.mainNode);
                    if (mainAccountInfo && mainAccountInfo.Account && mainAccountInfo.Account.TransactionHistory) {
                        const activationTx = mainAccountInfo.Account.TransactionHistory.find(tx => 
                            tx.TransactionType === 'AccountSet' && tx.Account === address);
                        if (activationTx) {
                            isCreatorWallet = true;
                        }
                    }
                } catch (err) {
                    console.warn('Could not determine if wallet is creator wallet:', err);
                }
            }
            
            // Enhance high-risk address cross-referencing
            let isHighRiskWallet = false;
            // Extract the base address without source tag for comparison
            const baseAddress = address.split(':')[0];
            
            if (HIGH_RISK_ADDRESSES.includes(baseAddress)) {
                isHighRiskWallet = true;
            }
            
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
                    
                    // Track wallet interactions and buying patterns
                    if (!walletInteractions.has(tx.Destination)) {
                        walletInteractions.set(tx.Destination, {
                            paymentCount: 0,
                            tokenTransfers: 0,
                            totalValue: 0,
                            firstInteractionTime: tx.date || Date.now(),
                            patterns: {
                                frequentSmallPayments: 0,
                                largeOneTimePayments: 0
                            }
                        });
                    }
                    
                    const interaction = walletInteractions.get(tx.Destination);
                    interaction.paymentCount++;
                    
                    // Track token transfers
                    if (typeof tx.Amount === 'object' && tx.Amount.currency) {
                        interaction.tokenTransfers++;
                    }
                    
                    // Track total value transferred
                    const txAmount = this._normalizeAmount(tx.Amount);
                    interaction.totalValue += txAmount;
                    
                    // Detect buying patterns
                    if (txAmount < 100) {
                        interaction.patterns.frequentSmallPayments++;
                    } else if (txAmount > 1000) {
                        interaction.patterns.largeOneTimePayments++;
                    }
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
                        
                        // Track trust relationships
                        if (!walletInteractions.has(trustIssuer)) {
                            walletInteractions.set(trustIssuer, {
                                paymentCount: 0,
                                tokenTransfers: 0,
                                totalValue: 0,
                                firstInteractionTime: tx.date || Date.now(),
                                patterns: {
                                    frequentSmallPayments: 0,
                                    largeOneTimePayments: 0
                                },
                                trustRelationship: true
                            });
                        } else {
                            walletInteractions.get(trustIssuer).trustRelationship = true;
                        }
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
                        
                        // Get wallet interaction data
                        const interactionData = walletInteractions.get(wallet) || {};
                        
                        // Cross-reference with high-risk addresses
                        // Extract the base address without source tag for comparison
                        const baseWallet = wallet.split(':')[0];
                        const isHighRisk = HIGH_RISK_ADDRESSES.includes(baseWallet);
                        
                        // Add additional properties for better visualization
                        const walletType = isHighRisk ? 'high-risk' : enhancedRisk.type || 'standard';
                        const isHighActivity = enhancedRisk.activityRisk > 0.6;
                        const isPotentiallyEarly = enhancedRisk.ageRisk < 0.3 && initialRisk > 0.5;
                        
                        // Add the wallet node with enhanced properties
                        this.addNode(wallet, 'wallet', {
                            radius: isHighRisk ? 12 : 8 + (initialRisk * 2), // Larger size for high-risk wallets
                            riskLevel: isHighRisk ? 1.0 : initialRisk,
                            walletType: walletType,
                            highActivity: isHighActivity,
                            potentialEarly: isPotentiallyEarly,
                            isHighRisk: isHighRisk, // Flag for high-risk addresses
                            isCreatorWallet: isCreatorWallet, // Flag for creator wallet
                            enhancedRiskData: enhancedRisk,
                            interactionData: interactionData, // Add interaction data to node
                            buyingPattern: this._analyzeBuyingPattern(interactionData)
                        });
                        
                        // Only go deeper for wallets that aren't too high risk
                        // This is to prevent getting stuck in obvious scam networks
                        if (initialRisk < 0.8) {
                            await this._analyzeNodeConnections(wallet, nextDepth);
                        }
                    }
                }
            }
            
            // Add direct connections between high-risk wallets in our network
            this._connectHighRiskWallets();
            
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
        
        // Extract the base address without source tag for comparison
        const baseAddress = address.split(':')[0];
        
        // Check if this is a known high-risk address
        if (HIGH_RISK_ADDRESSES.includes(baseAddress)) {
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
            
            // Cross-reference with known issuer addresses
            const issuedTokens = await xrplService.getIssuedTokens(address);
            if (issuedTokens.length > 0) {
                // This wallet is an issuer
                if (issuedTokens.length > RISK_FACTORS.wallet.manyIssuances.threshold) {
                    riskScore += RISK_FACTORS.wallet.manyIssuances.weight * 
                        Math.min(1, (issuedTokens.length - RISK_FACTORS.wallet.manyIssuances.threshold) / 5);
                }
                
                // Check if any issued tokens have suspicious patterns
                let suspiciousTokens = 0;
                for (const token of issuedTokens) {
                    if (this._hasTokenSuspiciousPattern(token)) {
                        suspiciousTokens++;
                    }
                }
                
                if (suspiciousTokens > 0) {
                    const suspiciousRatio = suspiciousTokens / issuedTokens.length;
                    riskScore += suspiciousRatio * RISK_FACTORS.wallet.suspiciousPattern.weight;
                }
            }
            
            // Cross-reference with creator wallets and previous issued tokens
            const creatorHistory = await this._checkCreatorHistory(address);
            if (creatorHistory.previousRugs > 0) {
                // If this wallet was previously involved in rug pulls, increase risk significantly
                riskScore += Math.min(0.5, creatorHistory.previousRugs * 0.15);
            }
            
            // Check for connections to known high-risk wallets
            const connectedAddresses = await this._getConnectedAddresses(address);
            const highRiskConnections = connectedAddresses.filter(addr => {
                // Extract base address without source tag
                const baseAddr = addr.split(':')[0];
                return HIGH_RISK_ADDRESSES.includes(baseAddr);
            });
            
            if (highRiskConnections.length > 0) {
                // If connected to known high-risk wallets, increase risk based on number of connections
                const connectionRisk = Math.min(0.7, highRiskConnections.length * 0.2);
                riskScore += connectionRisk;
            }
            
            // Check for creator wallet connection to issuer
            // If this wallet created the token issuer, it has higher risk
            if (this.networkData.mainNode && this.networkData.mainNode !== address) {
                try {
                    const mainAccountInfo = await xrplService.getAccountInfo(this.networkData.mainNode);
                    if (mainAccountInfo && mainAccountInfo.Account && mainAccountInfo.Account.TransactionHistory) {
                        const activationTx = mainAccountInfo.Account.TransactionHistory.find(tx => 
                            tx.TransactionType === 'AccountSet' && tx.Account === address);
                        if (activationTx) {
                            // This wallet created the issuer - significant risk factor
                            riskScore += 0.4;
                        }
                    }
                } catch (err) {
                    console.warn('Could not check creator wallet connection:', err);
                }
            }
            
            // Cap risk score at 1.0
            return Math.min(riskScore, 1.0);
        } catch (error) {
            console.error(`Error calculating wallet risk for ${address}:`, error);
            return 0.5; // Default medium risk on error
        }
    }

    /**
     * Check if a token has suspicious patterns
     * @param {object} token - Token information
     * @returns {boolean} - Whether the token has suspicious patterns
     * @private
     */
    _hasTokenSuspiciousPattern(token) {
        if (!token) return false;
        
        // Check currency name for suspicious terms
        if (token.currency) {
            const lowerCurrency = token.currency.toLowerCase();
            for (const flag of RISK_FACTORS.token.suspicious_name.flags) {
                if (lowerCurrency.includes(flag)) {
                    return true;
                }
            }
        }
        
        // Check token amount/supply patterns
        if (token.amount) {
            const amount = parseFloat(token.amount);
            // Extremely large supplies are often suspicious
            if (amount > 1_000_000_000_000) {
                return true;
            }
            
            // Unusual precise numbers can be suspicious
            const amountStr = amount.toString();
            if (amountStr.endsWith('000000000') || amountStr.endsWith('999999999')) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check a wallet's history as a creator/issuer
     * @param {string} address - XRPL address to check
     * @returns {Promise<object>} - Creator history information
     * @private
     */
    async _checkCreatorHistory(address) {
        const result = {
            tokens: [],
            previousRugs: 0,
            averageTokenLifetime: 0
        };
        
        try {
            // Set a timeout to prevent this function from hanging
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Creator history check timed out')), 10000);
            });
            
            // Get all tokens created by this address
            const issuedTokensPromise = xrplService.getIssuedTokens(address);
            
            // Race between the actual request and the timeout
            const issuedTokens = await Promise.race([issuedTokensPromise, timeoutPromise])
                .catch(err => {
                    console.warn(`Timeout or error checking issued tokens for ${address}: ${err.message}`);
                    return []; // Return empty array on timeout or error
                });
                
            result.tokens = issuedTokens || [];
            
            // Skip heavy processing if no tokens found or too many tokens (performance optimization)
            if (!issuedTokens || issuedTokens.length === 0 || issuedTokens.length > 10) {
                return result;
            }
            
            // For each token, try to determine if it was a rug pull
            // Limit the number of tokens analyzed to avoid performance issues
            const tokensToAnalyze = issuedTokens.slice(0, 3); // Only analyze up to 3 tokens
            let totalLifetime = 0;
            let countedTokens = 0;
            
            // Use Promise.all to process tokens in parallel
            const tokenAnalysisPromises = tokensToAnalyze.map(async token => {
                try {
                    // Calculate a rough token lifetime by looking at first and last transactions
                    const tokenTransactions = await xrplService.getTokenTransactions(token.currency, address, 20);
                    
                    if (tokenTransactions.length >= 3) {
                        // Get first and most recent transaction
                        const firstTx = tokenTransactions[tokenTransactions.length - 1];
                        const lastTx = tokenTransactions[0];
                        
                        if (firstTx.date && lastTx.date) {
                            const startTime = new Date(firstTx.date);
                            const endTime = new Date(lastTx.date);
                            const lifetimeDays = (endTime - startTime) / (1000 * 60 * 60 * 24);
                            
                            // Return results for aggregation
                            return {
                                lifetimeDays,
                                isRugPull: lifetimeDays < 7 && 
                                    (this._checkForHighInitialVolume(tokenTransactions) || 
                                     this._checkForSharpValueDrop(tokenTransactions))
                            };
                        }
                    }
                    return null;
                } catch (err) {
                    console.warn(`Error analyzing token ${token.currency}: ${err.message}`);
                    return null;
                }
            });
            
            // Wait for all token analyses to complete
            const tokenResults = await Promise.all(tokenAnalysisPromises);
            
            // Process results
            tokenResults.forEach(result => {
                if (result) {
                    totalLifetime += result.lifetimeDays;
                    countedTokens++;
                    
                    if (result.isRugPull) {
                        result.previousRugs++;
                    }
                }
            });
            
            // Calculate average token lifetime
            if (countedTokens > 0) {
                result.averageTokenLifetime = totalLifetime / countedTokens;
            }
            
            return result;
        } catch (error) {
            console.warn(`Error checking creator history for ${address}: ${error.message}`);
            return result; // Return the default result with empty data
        }
    }

    /**
     * Check token transactions for high initial volume (common in rug pulls)
     * @param {Array} transactions - Token transactions
     * @returns {boolean} - Whether high initial volume is detected
     * @private
     */
    _checkForHighInitialVolume(transactions) {
        // Requires at least 10 transactions to analyze
        if (!transactions || transactions.length < 10) return false;
        
        // Compare first 5 transactions volume with next 5
        const initialVolume = transactions.slice(transactions.length - 5).reduce((total, tx) => {
            return total + this._normalizeAmount(tx.Amount || 0);
        }, 0);
        
        const laterVolume = transactions.slice(transactions.length - 10, transactions.length - 5).reduce((total, tx) => {
            return total + this._normalizeAmount(tx.Amount || 0);
        }, 0);
        
        // If initial volume is at least 3x higher than later volume, flag as suspicious
        return initialVolume > laterVolume * 3;
    }

    /**
     * Check token transactions for sharp value drop (common in rug pulls)
     * @param {Array} transactions - Token transactions
     * @returns {boolean} - Whether sharp value drop is detected
     * @private
     */
    _checkForSharpValueDrop(transactions) {
        // Requires at least 15 transactions to analyze
        if (!transactions || transactions.length < 15) return false;
        
        // Try to find a pattern where value drops significantly in a short timeframe
        const values = transactions.map(tx => this._normalizeAmount(tx.Amount || 0));
        
        for (let i = 0; i < values.length - 5; i++) {
            const beforeDrop = values.slice(i, i + 3).reduce((a, b) => a + b, 0) / 3;
            const afterDrop = values.slice(i + 3, i + 6).reduce((a, b) => a + b, 0) / 3;
            
            // If value dropped by 70% or more, flag as suspicious
            if (afterDrop < beforeDrop * 0.3) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Get addresses connected to a wallet
     * @param {string} address - XRPL address to check
     * @returns {Promise<Array<string>>} - List of connected addresses
     * @private
     */
    async _getConnectedAddresses(address) {
        const connectedAddresses = new Set();
        
        try {
            // Get account transactions to identify connected wallets
            const transactions = await xrplService.getAccountTransactions(address, 50);
            
            for (const tx of transactions) {
                // Skip invalid transactions
                if (!tx || !tx.TransactionType) continue;
                
                // Add destination wallets
                if (tx.Destination && tx.Destination !== address) {
                    connectedAddresses.add(tx.Destination);
                }
                
                // Add source wallets if this wallet is the destination
                if (tx.Account && tx.Account !== address) {
                    connectedAddresses.add(tx.Account);
                }
                
                // Add trustline issuers
                if (tx.TransactionType === 'TrustSet' && tx.LimitAmount && tx.LimitAmount.issuer) {
                    connectedAddresses.add(tx.LimitAmount.issuer);
                }
            }
            
            return [...connectedAddresses];
        } catch (error) {
            console.error(`Error getting connected addresses for ${address}:`, error);
            return [];
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
        // Add progress tracking
        console.log('Starting final risk calculation...');
        
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
        
        console.log('Processing node risk scores...');
        
        // Batch processing to avoid UI blocking
        const batchSize = 20; // Process nodes in batches
        const nodes = [...this.networkData.nodes]; // Create a copy to safely iterate
        
        // Process all nodes in batches
        for (let i = 0; i < nodes.length; i += batchSize) {
            const batch = nodes.slice(i, i + batchSize);
            
            // First pass: Get base risk scores for this batch
            for (const node of batch) {
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
                    
                    // Known high-risk wallets always have maximum risk
                    if (node.isHighRisk || HIGH_RISK_ADDRESSES.includes(node.id.split(':')[0])) {
                        baseRisk = 1.0;
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
        }
        
        console.log('Processing wallet interconnections...');
        
        // Create a more optimized version of interconnected wallet detection
        // Only process wallets connected to the main node to reduce computation
        const mainNodeLinks = idToLinks.get(this.networkData.mainNode) || [];
        const firstLevelConnectionIds = new Set();
        
        // First, identify all wallets directly connected to the main node
        mainNodeLinks.forEach(link => {
            const connectedId = link.source === this.networkData.mainNode ? link.target : link.source;
            const connectedNode = nodeMap.get(connectedId);
            
            if (connectedNode && connectedNode.type === 'wallet') {
                firstLevelConnectionIds.add(connectedId);
            }
        });
        
        // Process wallet-to-wallet connections among first-level connections in batches
        const firstLevelWallets = [...firstLevelConnectionIds];
        const connectedWallets = new Map();
        
        for (let i = 0; i < firstLevelWallets.length; i += batchSize) {
            const batch = firstLevelWallets.slice(i, i + batchSize);
            
            batch.forEach(walletId => {
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
        }
        
        console.log('Finalizing risk calculations...');
        
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
        
        console.log('Final risk calculation complete');
    }

    /**
     * Generate findings based on the analysis
     * @private
     */
    _generateFindings() {
        this.findings = [];
        
        try {
            console.log('Generating analysis findings...');
            
            // Use Map instead of repeated array filters for better performance
            const walletNodes = new Map();
            const tokenNodes = new Map();
            const suspiciousLinks = [];
            const highRiskConnections = [];
            
            // First pass: categorize nodes and links once for faster access
            this.networkData.nodes.forEach(node => {
                if (node.type === 'wallet') {
                    walletNodes.set(node.id, node);
                } else if (node.type === 'token') {
                    tokenNodes.set(node.id, node);
                }
            });
            
            this.networkData.links.forEach(link => {
                const source = typeof link.source === 'object' ? link.source.id : link.source;
                const target = typeof link.target === 'object' ? link.target.id : link.target;
                
                if (link.suspicious) {
                    suspiciousLinks.push({
                        source,
                        target,
                        properties: link
                    });
                }
                
                if (link.highRiskConnection) {
                    highRiskConnections.push({
                        source,
                        target
                    });
                }
            });
            
            // Find nodes with highest risk scores
            const nodeRiskScores = [...walletNodes.values()]
                .map(node => ({
                    id: node.id,
                    riskLevel: node.riskLevel || 0,
                    properties: node
                }))
                .sort((a, b) => b.riskLevel - a.riskLevel);
            
            // Get top high-risk wallets for findings
            const highRiskWallets = nodeRiskScores
                .filter(node => node.riskLevel >= 0.7)
                .slice(0, 5);
            
            if (highRiskWallets.length > 0) {
                this.findings.push({
                    type: 'high_risk_wallets',
                    severity: 'high',
                    description: `Found ${highRiskWallets.length} high-risk wallet${highRiskWallets.length > 1 ? 's' : ''} in the network`,
                    details: highRiskWallets.map(wallet => ({
                        address: wallet.id,
                        riskScore: wallet.riskLevel.toFixed(2),
                        reason: this._getWalletRiskReason(wallet.properties)
                    }))
                });
            }
            
            // Check for known high-risk addresses
            const knownHighRiskWallets = [...walletNodes.values()]
                .filter(node => {
                    const baseAddress = node.id.split(':')[0];
                    return HIGH_RISK_ADDRESSES.includes(baseAddress);
                })
                .map(node => ({
                    id: node.id,
                    baseAddress: node.id.split(':')[0],
                    sourceTag: node.id.includes(':') ? node.id.split(':')[1] : null
                }));
            
            if (knownHighRiskWallets.length > 0) {
                this.findings.push({
                    type: 'known_high_risk_wallets',
                    severity: 'critical',
                    description: `Found ${knownHighRiskWallets.length} wallet${knownHighRiskWallets.length > 1 ? 's' : ''} from known high-risk list`,
                    details: knownHighRiskWallets.map(wallet => ({
                        address: wallet.id,
                        baseAddress: wallet.baseAddress,
                        sourceTag: wallet.sourceTag,
                        reason: 'Listed in known high-risk wallet registry'
                    }))
                });
            }
            
            // Find creator wallet if present
            const creatorWallets = [...walletNodes.values()]
                .filter(node => node.isCreatorWallet)
                .slice(0, 3); // Limit to top 3 for performance
            
            if (creatorWallets.length > 0) {
                this.findings.push({
                    type: 'creator_wallet_identified',
                    severity: 'high',
                    description: `Identified ${creatorWallets.length} creator wallet${creatorWallets.length > 1 ? 's' : ''} that activated the issuer address`,
                    details: creatorWallets.map(node => ({
                        address: node.id,
                        riskLevel: (node.riskLevel || 0).toFixed(2),
                        reason: 'This wallet created/activated the main address being analyzed'
                    }))
                });
            }
            
            // Early participant analysis - limit to top 10 for performance
            const earlyParticipants = [...walletNodes.values()]
                .filter(node => node.earlyParticipant)
                .sort((a, b) => (b.riskLevel || 0) - (a.riskLevel || 0))
                .slice(0, 10);
            
            const highRiskEarlyParticipants = earlyParticipants.filter(node => node.riskLevel >= 0.6);
            
            if (highRiskEarlyParticipants.length > 0) {
                this.findings.push({
                    type: 'high_risk_early_participants',
                    severity: 'high',
                    description: `Found ${highRiskEarlyParticipants.length} high-risk early participant${highRiskEarlyParticipants.length > 1 ? 's' : ''} in token transactions`,
                    details: highRiskEarlyParticipants.slice(0, 5).map(node => ({
                        address: node.id,
                        riskScore: (node.riskLevel || 0).toFixed(2),
                        earlyInfo: node.earlyTxInfo || 'Early participant',
                        reason: 'Early participant with suspicious transaction patterns'
                    }))
                });
            }
            
            // Token risks - limit to 10 for performance
            const tokenRisks = [...tokenNodes.values()]
                .map(node => ({
                    id: node.id,
                    name: node.name,
                    currency: node.currency,
                    issuer: node.issuer,
                    riskLevel: node.riskLevel || 0
                }))
                .sort((a, b) => b.riskLevel - a.riskLevel)
                .slice(0, 10);
            
            const highRiskTokens = tokenRisks.filter(token => token.riskLevel >= 0.6);
            
            if (highRiskTokens.length > 0) {
                this.findings.push({
                    type: 'high_risk_tokens',
                    severity: 'high',
                    description: `Found ${highRiskTokens.length} high-risk token${highRiskTokens.length > 1 ? 's' : ''}`,
                    details: highRiskTokens.map(token => ({
                        currency: token.currency,
                        issuer: token.issuer,
                        riskScore: token.riskLevel.toFixed(2)
                    }))
                });
            }
            
            // Only process top suspicious connections for performance
            if (suspiciousLinks.length > 0) {
                const limitedLinks = suspiciousLinks.slice(0, 10);
                this.findings.push({
                    type: 'suspicious_connections',
                    severity: 'medium',
                    description: `Found ${suspiciousLinks.length} suspicious connection${suspiciousLinks.length > 1 ? 's' : ''} between wallets`,
                    details: limitedLinks.map(link => ({
                        source: link.source,
                        target: link.target,
                        transactionType: link.properties.transactionType || 'unknown'
                    }))
                });
            }
            
            // High-risk connections
            if (highRiskConnections.length > 0) {
                this.findings.push({
                    type: 'high_risk_wallet_connections',
                    severity: 'critical',
                    description: `Found ${highRiskConnections.length} connection${highRiskConnections.length > 1 ? 's' : ''} between high-risk wallets`,
                    details: {
                        connectionCount: highRiskConnections.length,
                        connections: highRiskConnections.slice(0, 10) // Limit to 10 connections
                    }
                });
            }
            
            // Analyze network metrics
            const networkRisk = this._calculateNetworkRisk();
            const overallRiskLevel = this._getOverallRiskLevel(networkRisk);
            
            this.findings.push({
                type: 'network_risk_assessment',
                severity: overallRiskLevel,
                description: `Overall network risk assessment: ${overallRiskLevel.toUpperCase()}`,
                details: {
                    riskScore: networkRisk.toFixed(2),
                    suspiciousConnections: suspiciousLinks.length,
                    connectedWallets: walletNodes.size - 1, // Exclude main node
                    highRiskWalletCount: highRiskWallets.length,
                    highRiskTokenCount: highRiskTokens.length,
                    highRiskRegistryMatches: knownHighRiskWallets.length
                }
            });
            
            console.log(`Generated ${this.findings.length} findings`);
            
        } catch (error) {
            console.error('Error generating findings:', error);
            this.findings.push({
                type: 'error',
                severity: 'low',
                description: 'Error generating complete findings',
                details: { error: error.message }
            });
        }
    }

    /**
     * Get textual description of why a wallet is high risk
     * @param {object} walletNode - Wallet node data
     * @returns {string} - Risk reason
     * @private
     */
    _getWalletRiskReason(walletNode) {
        if (!walletNode) return 'Unknown reason';
        
        const reasons = [];
        
        if (HIGH_RISK_ADDRESSES.includes(walletNode.id)) {
            reasons.push('Known high-risk wallet');
        }
        
        if (walletNode.enhancedRiskData) {
            if (walletNode.enhancedRiskData.activityRisk > 0.7) {
                reasons.push('Suspicious transaction activity');
            }
            
            if (walletNode.enhancedRiskData.ageRisk > 0.7) {
                reasons.push('Recently created wallet');
            }
            
            if (walletNode.enhancedRiskData.connectionRisk > 0.7) {
                reasons.push('Connected to high-risk wallets');
            }
        }
        
        if (walletNode.walletType === 'issuer' && walletNode.riskLevel > 0.6) {
            reasons.push('High-risk token issuer');
        }
        
        if (walletNode.earlyParticipant && walletNode.riskLevel > 0.6) {
            reasons.push('High-risk early participant');
        }
        
        if (walletNode.buyingPattern && walletNode.buyingPattern.risk > 0.5) {
            reasons.push(`Suspicious buying pattern: ${walletNode.buyingPattern.pattern}`);
        }
        
        if (walletNode.interactionData && walletNode.interactionData.totalValue > 1000 && walletNode.riskLevel > 0.5) {
            reasons.push('High transaction volume with suspicious patterns');
        }
        
        return reasons.length > 0 ? reasons.join(', ') : 'Multiple risk factors';
    }

    /**
     * Calculate overall network risk
     * @returns {number} - Risk score (0-1)
     * @private
     */
    _calculateNetworkRisk() {
        // Count high risk nodes and connections
        const totalNodes = this.networkData.nodes.length;
        const walletNodes = this.networkData.nodes.filter(node => node.type === 'wallet');
        const highRiskNodes = this.networkData.nodes.filter(node => node.riskLevel >= 0.7);
        
        // Calculate high risk ratio (weight more heavily for accuracy)
        const highRiskRatio = totalNodes > 0 ? Math.pow(highRiskNodes.length / totalNodes, 0.8) : 0;
        
        // Check for known high-risk wallets (these have highest impact)
        const knownHighRiskWallets = this.networkData.nodes.filter(node => {
            if (node.type !== 'wallet') return false;
            const baseAddress = node.id.split(':')[0];
            return HIGH_RISK_ADDRESSES.includes(baseAddress);
        });
        
        // Known high-risk wallets are a strong indicator
        const knownHighRiskImpact = knownHighRiskWallets.length > 0 ? 
            Math.min(0.8, 0.3 + (knownHighRiskWallets.length * 0.1)) : 0;
            
        // Analyze suspicious connections 
        const suspiciousLinks = this.networkData.links.filter(link => link.suspicious);
        const suspiciousLinkRatio = suspiciousLinks.length > 0 ? 
            suspiciousLinks.length / Math.max(5, this.networkData.links.length) : 0;
            
        // Analyze early participants
        const earlyParticipants = this.networkData.nodes.filter(node => node.earlyParticipant);
        const highRiskEarlyParticipants = earlyParticipants.filter(node => node.riskLevel >= 0.6);
        const earlyParticipantRiskRatio = earlyParticipants.length > 0 ? 
            Math.pow(highRiskEarlyParticipants.length / earlyParticipants.length, 0.7) : 0;
        
        // Analyze token risks
        const tokenNodes = this.networkData.nodes.filter(node => node.type === 'token');
        const highRiskTokens = tokenNodes.filter(node => node.riskLevel >= 0.6);
        const tokenRiskRatio = tokenNodes.length > 0 ? 
            Math.pow(highRiskTokens.length / tokenNodes.length, 0.9) : 0;
            
        // Examine creator wallet risk
        const creatorWallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && node.isCreatorWallet);
        let creatorRisk = 0;
        
        if (creatorWallets.length > 0) {
            creatorRisk = creatorWallets.reduce((sum, wallet) => sum + wallet.riskLevel, 0) / creatorWallets.length;
            creatorRisk = Math.pow(creatorRisk, 0.8); // Slightly reduce impact with power function
        }
        
        // Check wallet interconnections (highly interconnected networks are riskier)
        const interconnectionScore = this._calculateInterconnectionScore();
        
        // Calculate weighted risk score - adjust weights based on importance
        // Known high-risk wallets have highest impact, followed by suspicious connections and early participants
        let finalRiskScore = 0;
        
        if (knownHighRiskImpact > 0) {
            // When known high-risk wallets are present, they become the dominant factor
            finalRiskScore = 
                (knownHighRiskImpact * 0.5) +
                (highRiskRatio * 0.1) +
                (suspiciousLinkRatio * 0.15) +
                (earlyParticipantRiskRatio * 0.1) +
                (tokenRiskRatio * 0.1) +
                (creatorRisk * 0.05);
                
            // Adjust for interconnection to increase risk even further if interconnected
            finalRiskScore = finalRiskScore * (1 + (interconnectionScore * 0.5));
        } else {
            // Normal calculation when no known high-risk wallets are present
            finalRiskScore = 
                (highRiskRatio * 0.25) +
                (suspiciousLinkRatio * 0.25) +
                (earlyParticipantRiskRatio * 0.2) +
                (tokenRiskRatio * 0.15) +
                (interconnectionScore * 0.1) +
                (creatorRisk * 0.05);
        }
        
        // Ensure score is capped at 1.0
        return Math.min(1.0, finalRiskScore);
    }
    
    /**
     * Calculate the interconnection score of wallets
     * Higher scores indicate more interconnected networks (riskier)
     * @returns {number} - Interconnection score (0-1)
     * @private
     */
    _calculateInterconnectionScore() {
        const wallets = this.networkData.nodes.filter(node => 
            node.type === 'wallet' && node.id !== this.networkData.mainNode);
            
        if (wallets.length < 3) {
            return 0; // Too few wallets to analyze interconnections
        }
        
        // Count wallet-to-wallet connections
        let walletToWalletLinks = 0;
        const walletIds = new Set(wallets.map(wallet => wallet.id));
        
        this.networkData.links.forEach(link => {
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;
            
            if (walletIds.has(sourceId) && walletIds.has(targetId)) {
                walletToWalletLinks++;
            }
        });
        
        // Calculate theoretical maximum connections (complete graph)
        const maxPossibleConnections = (wallets.length * (wallets.length - 1)) / 2;
        
        // Normalize to 0-1 range, with adjustment for more realistic scoring
        // Few connections in a large network should still yield a low score
        let interconnectionRatio = walletToWalletLinks / Math.max(1, maxPossibleConnections);
        
        // Apply sigmoid-like function to create better distribution
        // This makes the middle range more sensitive and floors/ceilings the extremes
        interconnectionRatio = interconnectionRatio / (0.2 + interconnectionRatio);
        
        return Math.min(1.0, interconnectionRatio);
    }

    /**
     * Convert risk score to descriptive level
     * @param {number} riskScore - Risk score (0-1)
     * @returns {string} - Risk level description (low, medium, high, critical)
     * @private
     */
    _getOverallRiskLevel(riskScore) {
        if (riskScore >= 0.8) return 'critical';
        if (riskScore >= 0.6) return 'high';
        if (riskScore >= 0.4) return 'medium';
        return 'low';
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

    /**
     * Analyze buying patterns to detect suspicious behavior
     * @param {object} interactionData - Data about wallet interactions
     * @returns {object} Pattern analysis results
     * @private
     */
    _analyzeBuyingPattern(interactionData) {
        if (!interactionData) return { risk: 0, pattern: 'unknown' };
        
        const { paymentCount, tokenTransfers, totalValue, patterns } = interactionData;
        let patternRisk = 0;
        let patternType = 'normal';
        
        // Check for pump & dump patterns (many small buys)
        if (patterns.frequentSmallPayments > 5) {
            patternRisk += 0.3;
            patternType = 'frequent_small_buys';
        }
        
        // Check for whale manipulation (few large transactions)
        if (patterns.largeOneTimePayments > 1 && paymentCount < 5) {
            patternRisk += 0.4;
            patternType = 'whale_pattern';
        }
        
        // Check for high token transfer ratio
        if (tokenTransfers > 0 && paymentCount > 0) {
            const tokenRatio = tokenTransfers / paymentCount;
            if (tokenRatio > 0.8) {
                patternRisk += 0.2;
                patternType = patternType === 'normal' ? 'token_focused' : `${patternType}_token_focused`;
            }
        }
        
        // Check for early / rapid interactions
        if (interactionData.trustRelationship && paymentCount > 3 && totalValue > 500) {
            patternRisk += 0.3;
            patternType = patternType === 'normal' ? 'rapid_trust_activity' : `${patternType}_with_trust`;
        }
        
        return {
            risk: Math.min(patternRisk, 1.0),
            pattern: patternType,
            summary: `${patternType} (${Math.round(patternRisk * 100)}% risk)`
        };
    }

    /**
     * Connect high-risk wallets to each other in the network visualization
     * This ensures that known suspicious wallets show their relationships
     * @private
     */
    _connectHighRiskWallets() {
        try {
            // Get all high-risk wallet nodes in our current network
            const highRiskWallets = this.networkData.nodes.filter(node => 
                node.type === 'wallet' && 
                (node.isHighRisk || HIGH_RISK_ADDRESSES.includes(node.id.split(':')[0]))
            );
            
            // Skip if there are fewer than 2 high-risk wallets
            if (highRiskWallets.length < 2) {
                return;
            }
            
            console.log(`Connecting ${highRiskWallets.length} high-risk wallets to each other`);
            
            // Connect each high-risk wallet to every other high-risk wallet
            for (let i = 0; i < highRiskWallets.length; i++) {
                for (let j = i + 1; j < highRiskWallets.length; j++) {
                    const wallet1 = highRiskWallets[i];
                    const wallet2 = highRiskWallets[j];
                    
                    // Add a high-risk connection between these wallets
                    this._addConnection(wallet1.id, wallet2.id, {
                        value: 2, // Medium strength connection
                        suspicious: true, // Always mark as suspicious
                        transactionType: 'HighRiskConnection',
                        highRiskConnection: true
                    });
                }
            }
            
            // Also connect all high-risk wallets to the main node if they aren't already
            for (const wallet of highRiskWallets) {
                if (wallet.id !== this.networkData.mainNode) {
                    // Check if connection already exists
                    const existingConnection = this.networkData.links.some(link => 
                        (link.source === wallet.id && link.target === this.networkData.mainNode) ||
                        (link.target === wallet.id && link.source === this.networkData.mainNode)
                    );
                    
                    if (!existingConnection) {
                        this._addConnection(this.networkData.mainNode, wallet.id, {
                            value: 3, // Stronger connection to main node
                            suspicious: true,
                            transactionType: 'HighRiskMainConnection',
                            highRiskConnection: true
                        });
                    }
                }
            }
            
            // Now connect regular related wallets too (enhancement)
            this._connectRelatedWallets();
        } catch (error) {
            console.error('Error connecting high-risk wallets:', error);
        }
    }
    
    /**
     * Connect related wallets to each other based on transaction history
     * This ensures that transaction networks are properly visualized
     * @private
     */
    _connectRelatedWallets() {
        try {
            // Get all wallet nodes excluding the main node
            const wallets = this.networkData.nodes.filter(node => 
                node.type === 'wallet' && node.id !== this.networkData.mainNode
            );
            
            // Skip if there are too few wallets
            if (wallets.length < 2) {
                return;
            }
            
            console.log(`Checking relationships between ${wallets.length} wallets`);
            
            // Create a map of wallets with their interaction data
            const walletInteractionMap = new Map();
            
            // Collect all wallets with interaction data
            wallets.forEach(wallet => {
                if (wallet.interactionData && (wallet.interactionData.paymentCount > 0 || wallet.interactionData.tokenTransfers > 0)) {
                    walletInteractionMap.set(wallet.id, wallet);
                }
            });
            
            // Find wallets that have similar interaction patterns or transaction timing
            for (let i = 0; i < wallets.length; i++) {
                const wallet1 = wallets[i];
                
                // Skip wallets without interaction data
                if (!wallet1.interactionData) continue;
                
                for (let j = i + 1; j < wallets.length; j++) {
                    const wallet2 = wallets[j];
                    
                    // Skip wallets without interaction data
                    if (!wallet2.interactionData) continue;
                    
                    // Skip if both wallets are high-risk (already connected)
                    if ((wallet1.isHighRisk || HIGH_RISK_ADDRESSES.includes(wallet1.id.split(':')[0])) && 
                        (wallet2.isHighRisk || HIGH_RISK_ADDRESSES.includes(wallet2.id.split(':')[0]))) {
                        continue;
                    }
                    
                    // Check for similar transaction timing
                    const timeDiff = Math.abs(wallet1.interactionData.firstInteractionTime - wallet2.interactionData.firstInteractionTime);
                    const timeDiffHours = timeDiff / (1000 * 60 * 60);
                    
                    // Check if wallets have similar transaction patterns (timing within 24 hours)
                    // or if they have similar buying patterns
                    const similarTiming = timeDiffHours < 24;
                    const similarPatterns = wallet1.buyingPattern && wallet2.buyingPattern && 
                                           wallet1.buyingPattern.pattern === wallet2.buyingPattern.pattern;
                    
                    // Connect wallets with similar patterns
                    if (similarTiming || similarPatterns) {
                        this._addConnection(wallet1.id, wallet2.id, {
                            value: 1.5, // Lighter connection than high-risk
                            suspicious: false,
                            transactionType: 'RelatedWallets',
                            relatedConnection: true
                        });
                    }
                }
            }
            
            // Connect early participants with each other
            const earlyParticipants = wallets.filter(wallet => wallet.earlyParticipant);
            for (let i = 0; i < earlyParticipants.length; i++) {
                for (let j = i + 1; j < earlyParticipants.length; j++) {
                    this._addConnection(earlyParticipants[i].id, earlyParticipants[j].id, {
                        value: 1.5,
                        suspicious: earlyParticipants[i].riskLevel > 0.6 || earlyParticipants[j].riskLevel > 0.6,
                        transactionType: 'EarlyParticipants',
                        earlyParticipantConnection: true
                    });
                }
            }
            
            // Connect wallets that interacted with the same tokens
            const tokenConnections = new Map(); // Map of token ID to list of connected wallets
            
            // Find wallets connected to the same tokens
            this.networkData.links.forEach(link => {
                const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                
                // Find node objects
                const sourceNode = this.networkData.nodes.find(n => n.id === sourceId);
                const targetNode = this.networkData.nodes.find(n => n.id === targetId);
                
                // Check if this is a wallet-to-token connection
                if (sourceNode && targetNode && 
                   ((sourceNode.type === 'wallet' && targetNode.type === 'token') ||
                    (sourceNode.type === 'token' && targetNode.type === 'wallet'))) {
                    
                    const tokenId = sourceNode.type === 'token' ? sourceId : targetId;
                    const walletId = sourceNode.type === 'wallet' ? sourceId : targetId;
                    
                    // Add to token connections map
                    if (!tokenConnections.has(tokenId)) {
                        tokenConnections.set(tokenId, []);
                    }
                    tokenConnections.get(tokenId).push(walletId);
                }
            });
            
            // Connect wallets that interacted with the same tokens
            tokenConnections.forEach((connectedWallets, tokenId) => {
                if (connectedWallets.length >= 2) {
                    // Connect wallets that interacted with the same token
                    for (let i = 0; i < connectedWallets.length; i++) {
                        for (let j = i + 1; j < connectedWallets.length; j++) {
                            // Skip connecting the main node to other wallets (already connected)
                            if (connectedWallets[i] === this.networkData.mainNode || 
                                connectedWallets[j] === this.networkData.mainNode) {
                                continue;
                            }
                            
                            this._addConnection(connectedWallets[i], connectedWallets[j], {
                                value: 1, // Light connection
                                suspicious: false,
                                transactionType: 'SharedToken',
                                sharedTokenConnection: true,
                                tokenId: tokenId
                            });
                        }
                    }
                }
            });
            
        } catch (error) {
            console.error('Error connecting related wallets:', error);
        }
    }
}

// Create and export a singleton instance
const networkAnalyzer = new NetworkAnalyzer();
export default networkAnalyzer; 