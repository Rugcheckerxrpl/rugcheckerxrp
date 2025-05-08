/**
 * XRPL Service
 * Handles connection and interaction with the XRP Ledger
 */

import { XRPL_CONFIG, API_ENDPOINTS, VALIDATORS } from './config.js';

// We'll use the Bithomp xrpl-api library for direct connections
// For this demo, we'll simulate the API calls

// Simplified API client for XRPL
class XRPLService {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.connectionStatus = 'disconnected';
        this.networkType = 'mainnet'; // 'testnet' or 'devnet' or 'mainnet'
        this.servers = {
            mainnet: 'wss://xrplcluster.com',
            testnet: 'wss://s.altnet.rippletest.net:51233',
            devnet: 'wss://s.devnet.rippletest.net:51233'
        };
    }

    /**
     * Connect to the XRP Ledger
     * @param {string} networkType - 'mainnet', 'testnet', or 'devnet'
     * @returns {Promise<boolean>} - Connection result
     */
    async connect(networkType = null) {
        try {
            if (networkType) {
                this.networkType = networkType;
            }

            // If xrpl.js library is not loaded, load it
            if (typeof xrpl === 'undefined') {
                await this._loadXrplLibrary();
            }

            const server = this.servers[this.networkType];
            this.client = new xrpl.Client(server);
            
            await this.client.connect();
            this.isConnected = true;
            this.connectionStatus = `connected to ${this.networkType}`;
            
            console.log(`Connected to XRPL ${this.networkType} at ${server}`);
            return true;
        } catch (error) {
            console.error('Error connecting to XRPL:', error);
            this.connectionStatus = `connection failed: ${error.message}`;
            this.isConnected = false;
            throw error;
        }
    }

    /**
     * Disconnect from the XRP Ledger
     */
    async disconnect() {
        if (this.client && this.isConnected) {
            await this.client.disconnect();
            this.isConnected = false;
            this.connectionStatus = 'disconnected';
            console.log('Disconnected from XRPL');
        }
    }

    /**
     * Load the XRPL library dynamically
     * @private
     */
    async _loadXrplLibrary() {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/xrpl@2.7.0/build/xrpl-latest-min.js';
            script.onload = () => {
                console.log('XRPL library loaded successfully');
                resolve();
            };
            script.onerror = (error) => {
                console.error('Failed to load XRPL library:', error);
                reject(new Error('Failed to load XRPL library'));
            };
            document.head.appendChild(script);
        });
    }

    /**
     * Check if an address is a valid XRPL address
     * @param {string} address - XRPL address to validate
     * @returns {boolean} - Whether the address is valid
     */
    isValidAddress(address) {
        if (typeof xrpl === 'undefined') {
            // Simple regex check if library not loaded
            const xrplAddressRegex = /^r[A-Za-z0-9]{24,34}$/;
            return xrplAddressRegex.test(address);
        }
        
        return xrpl.isValidAddress(address);
    }

    /**
     * Get account information
     * @param {string} address - XRPL address
     * @returns {Promise<object>} - Account information
     */
    async getAccountInfo(address) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            const response = await this.client.request({
                command: 'account_info',
                account: address,
                ledger_index: 'validated'
            });
            
            return response.result.account_data;
        } catch (error) {
            console.error('Error fetching account info:', error);
            throw error;
        }
    }

    /**
     * Get account transactions
     * @param {string} address - XRPL address
     * @param {number} limit - Maximum number of transactions to return
     * @returns {Promise<Array>} - Array of transactions
     */
    async getAccountTransactions(address, limit = 20) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            const response = await this.client.request({
                command: 'account_tx',
                account: address,
                limit: limit
            });
            
            return response.result.transactions.map(tx => tx.tx);
        } catch (error) {
            console.error('Error fetching account transactions:', error);
            throw error;
        }
    }

    /**
     * Fetch the earliest transactions for an account
     * @param {string} address - XRPL address
     * @param {number} limit - Maximum number of transactions to return
     * @returns {Promise<{transactions: Array, hasMore: boolean, marker: any}>} - Earliest transactions, flag for more, and marker
     */
    async fetchEarlyTransactions(address, limit = 100) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // Use forward=true to get oldest transactions first
            const response = await this.client.request({
                command: 'account_tx',
                account: address,
                limit: limit,
                forward: true,
                ledger_index_min: -1, // Start from the earliest ledger
                ledger_index_max: -1  // Up to the most recent validated ledger
            });
            
            return {
                transactions: response.result.transactions.map(tx => tx.tx),
                hasMore: !!response.result.marker,
                marker: response.result.marker
            };
        } catch (error) {
            console.error('Error fetching early transactions:', error);
            throw error;
        }
    }

    /**
     * Fetch the most recent transactions for an account
     * @param {string} address - XRPL address
     * @param {number} limit - Maximum number of transactions to return
     * @param {any} marker - Marker for pagination
     * @returns {Promise<{transactions: Array, hasMore: boolean, marker: any}>} - Recent transactions, flag for more, and marker
     */
    async fetchRecentTransactions(address, limit = 100, marker = null) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // Use forward=false (default) to get most recent transactions first
            const request = {
                command: 'account_tx',
                account: address,
                limit: limit,
                ledger_index_min: -1,
                ledger_index_max: -1
            };
            
            if (marker) {
                request.marker = marker;
            }
            
            const response = await this.client.request(request);
            
            return {
                transactions: response.result.transactions.map(tx => tx.tx),
                hasMore: !!response.result.marker,
                marker: response.result.marker
            };
        } catch (error) {
            console.error('Error fetching recent transactions:', error);
            throw error;
        }
    }

    /**
     * Get account balances including tokens
     * @param {string} address - XRPL address
     * @returns {Promise<object>} - Account balances
     */
    async getAccountBalances(address) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // Get XRP balance
            const accountInfo = await this.getAccountInfo(address);
            const xrpBalance = xrpl.dropsToXrp(accountInfo.Balance);
            
            // Get token balances (trustlines)
            const lines = await this.client.request({
                command: 'account_lines',
                account: address
            });
            
            const tokens = lines.result.lines.map(line => ({
                currency: line.currency,
                issuer: line.account,
                value: line.balance,
                limit: line.limit
            }));
            
            return {
                xrp: xrpBalance,
                tokens: tokens
            };
        } catch (error) {
            console.error('Error fetching account balances:', error);
            throw error;
        }
    }

    /**
     * Get account objects (trustlines, offers, etc.)
     * @param {string} address - XRPL address
     * @returns {Promise<Array>} - Account objects
     */
    async getAccountObjects(address) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            const response = await this.client.request({
                command: 'account_objects',
                account: address
            });
            
            return response.result.account_objects;
        } catch (error) {
            console.error('Error fetching account objects:', error);
            throw error;
        }
    }

    /**
     * Get account trustlines (tokens they trust)
     * @param {string} address - XRPL address
     * @returns {Promise<Array>} - Trustlines
     */
    async getAccountTrustlines(address) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            const response = await this.client.request({
                command: 'account_lines',
                account: address
            });
            
            return response.result.lines;
        } catch (error) {
            console.error('Error fetching trustlines:', error);
            throw error;
        }
    }

    /**
     * Get tokens connected to an account
     * @param {string} address - XRPL address
     * @returns {Promise<Array>} - Connected tokens
     */
    async getIssuedTokens(address) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // This is more complex as we need to search for trustlines
            // where this account is the issuer
            const response = await this.client.request({
                command: 'account_currencies',
                account: address,
                strict: true
            });
            
            const issuedCurrencies = response.result.send_currencies || [];
            const tokens = [];
            
            // For each currency, get more details
            for (const currency of issuedCurrencies) {
                // Get all trustlines for this currency and issuer
                const trustlineResponse = await this.client.request({
                    command: 'gateway_balances',
                    account: address,
                    hotwallet: [address],
                    ledger_index: 'validated'
                });
                
                if (trustlineResponse.result.obligations) {
                    for (const [curr, amount] of Object.entries(trustlineResponse.result.obligations)) {
                        tokens.push({
                            currency: curr,
                            amount: amount,
                            issuer: address
                        });
                    }
                }
            }
            
            return tokens;
        } catch (error) {
            console.error('Error fetching connected tokens:', error);
            throw error;
        }
    }

    /**
     * Find token connections between accounts
     * @param {string} address1 - First XRPL address
     * @param {string} address2 - Second XRPL address
     * @returns {Promise<Array>} - Shared tokens
     */
    async findTokenConnections(address1, address2) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // Get both accounts' tokens
            const tokens1 = await this.getAccountTrustlines(address1);
            const tokens2 = await this.getAccountTrustlines(address2);
            
            // Find shared tokens
            const sharedTokens = [];
            
            for (const token1 of tokens1) {
                for (const token2 of tokens2) {
                    if (token1.currency === token2.currency && 
                        token1.account === token2.account) {
                        sharedTokens.push({
                            currency: token1.currency,
                            issuer: token1.account
                        });
                        break;
                    }
                }
            }
            
            return sharedTokens;
        } catch (error) {
            console.error('Error finding token connections:', error);
            throw error;
        }
    }

    /**
     * Get transaction details
     * @param {string} txHash - Transaction hash
     * @returns {Promise<object>} - Transaction details
     */
    async getTransaction(txHash) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            const response = await this.client.request({
                command: 'tx',
                transaction: txHash
            });
            
            return response.result;
        } catch (error) {
            console.error('Error fetching transaction:', error);
            throw error;
        }
    }

    // Get account NFTs from XRPL
    async getAccountNFTs(address) {
        if (!this.isValidAddress(address)) {
            throw new Error('Invalid XRPL address');
        }

        try {
            const response = await fetch(`${API_ENDPOINTS.xrpScan}/account/${address}/nfts`);
            if (!response.ok) {
                throw new Error('Failed to fetch account NFTs');
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching account NFTs:', error);
            throw error;
        }
    }

    // Get token info from OnTheDEX API
    async getTokenInfo(currency, issuer) {
        try {
            // Use the xrpl.to API instead of OnTheDEX
            const response = await fetch(`https://api.xrpl.to/api/token/${issuer}_${currency}`);
            if (!response.ok) {
                throw new Error('Failed to fetch token info');
            }
            const data = await response.json();
            
            // Map the response to our expected format
            if (data && data.res === "success" && data.token) {
                return {
                    data: {
                        name: data.token.name || currency,
                        issuer: issuer,
                        currency: currency,
                        firstLedgerTime: data.token.dateon ? Math.floor(data.token.dateon/1000) : null,
                        firstLedgerHash: data.token.md5 || null,
                        holders: data.token.holders || 0,
                        trustlines: data.token.trustlines || 0,
                        verified: data.token.verified || false,
                        domain: data.token.domain || null,
                        tags: data.token.tags || []
                    }
                };
            } else {
                throw new Error('Invalid token data format');
            }
        } catch (error) {
            console.error('Error fetching token info:', error);
            throw error;
        }
    }

    /**
     * Fetch the first transactions related to a token to determine its issue date
     * @param {string} issuer - The token issuer address
     * @param {string} currency - The token currency code
     * @param {number} limit - Maximum number of transactions to return
     * @returns {Promise<Array>} - Array of earliest token transactions
     */
    async fetchTokenFirstTxs(issuer, currency, limit = 10) {
        if (!this.isConnected) {
            await this.connect();
        }

        try {
            // First try to get the token info from OnTheDEX API which may have the issue date
            try {
                const tokenInfo = await this.getTokenInfo(currency, issuer);
                if (tokenInfo && tokenInfo.data && tokenInfo.data.firstLedgerTime) {
                    return [{
                        date: new Date(tokenInfo.data.firstLedgerTime * 1000), // Convert Unix timestamp to JS Date
                        type: 'TrustSet',
                        tx_hash: tokenInfo.data.firstLedgerHash || 'unknown'
                    }];
                }
            } catch (err) {
                console.log(`No token info available from API for ${currency}.${issuer}`);
                // Continue to manual search if API doesn't have the data
            }
            
            // Get the oldest transactions for the issuer
            const { transactions } = await this.fetchEarlyTransactions(issuer, 200);
            
            // Filter for transactions related to the token (TrustSet, Payment with the currency)
            const tokenTxs = transactions.filter(tx => {
                // Check for TrustSet with this currency
                if (tx.TransactionType === 'TrustSet' && 
                    tx.LimitAmount && 
                    tx.LimitAmount.currency === currency &&
                    tx.LimitAmount.issuer === issuer) {
                    return true;
                }
                
                // Check for Payment with this currency
                if (tx.TransactionType === 'Payment' && 
                    tx.Amount && 
                    typeof tx.Amount === 'object' &&
                    tx.Amount.currency === currency && 
                    tx.Amount.issuer === issuer) {
                    return true;
                }
                
                return false;
            });
            
            // Convert transactions to a simpler format with dates
            return tokenTxs.slice(0, limit).map(tx => ({
                date: new Date(tx.date * 1000 + 946684800000), // Convert Ripple epoch to JS Date
                type: tx.TransactionType,
                tx_hash: tx.hash
            }));
        } catch (error) {
            console.error(`Error fetching token first transactions for ${currency}.${issuer}:`, error);
            throw error;
        }
    }

    // Get token price data from OnTheDEX API
    async getTokenPriceData(currency, issuer, quote = 'XRP') {
        try {
            const response = await fetch(`${API_ENDPOINTS.onTheDex}/ticker/${currency}.${issuer}:${quote}`);
            if (!response.ok) {
                throw new Error('Failed to fetch token price data');
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching token price data:', error);
            throw error;
        }
    }

    // Check for connections between accounts (flow of funds)
    async getAccountConnections(address, depth = 1) {
        if (!this.isValidAddress(address)) {
            throw new Error('Invalid XRPL address');
        }

        try {
            // This would normally involve complex logic to analyze transactions
            // For the demo, we'll return a simplified response with connected accounts
            const txs = await this.getAccountTransactions(address, 50);
            
            const connections = new Set();
            txs.forEach(tx => {
                if (tx.Destination && tx.Destination !== address) {
                    connections.add(tx.Destination);
                }
                if (tx.Account && tx.Account !== address) {
                    connections.add(tx.Account);
                }
            });
            
            return {
                account: address,
                connections: Array.from(connections).map(connectedAddress => ({
                    address: connectedAddress,
                    transactions: txs.filter(tx => 
                        tx.Destination === connectedAddress || tx.Account === connectedAddress
                    ).length
                }))
            };
        } catch (error) {
            console.error('Error analyzing account connections:', error);
            throw error;
        }
    }
}

// Create and export a singleton instance
const xrplService = new XRPLService();
export default xrplService; 