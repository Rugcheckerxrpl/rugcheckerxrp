/**
 * Configuration for RugCheckerX Application
 */

// XRPL Configuration
export const XRPL_CONFIG = {
    // XRPL Nodes
    nodes: {
        mainnet: 'wss://xrplcluster.com',
        testnet: 'wss://s.altnet.rippletest.net:51233',
        devnet: 'wss://s.devnet.rippletest.net:51233'
    },
    // Default options
    options: {
        connectionTimeout: 20000,
        maxConnectionAttempts: 3,
        defaultLedgerVersion: 'validated'
    }
};

// API Endpoints
export const API_ENDPOINTS = {
    // XRPL Scan API
    xrpScan: 'https://api.xrpscan.com/api/v1',
    // Bithomp API
    bithomp: 'https://api.bithomp.com/v2',
    // XRPlorer API
    xrplorer: 'https://api.xrplorer.com/v1',
    // RugCheckerX Own API (future)
    rugcheckerx: 'https://api.rugcheckerx.com/v1'
};

// Network Risk Factors
export const RISK_FACTORS = {
    // Token risk factors
    token: {
        lowSupply: { weight: 0.6, threshold: 100000 }, // Low supply can indicate exclusivity or scam
        highSupply: { weight: 0.3, threshold: 10000000000 }, // Very high supply can be a risk factor
        limitedHolders: { weight: 0.8, threshold: 10 }, // Very few holders is a risk
        highConcentration: { weight: 0.9, threshold: 70 }, // % in top 3 wallets
        recentCreation: { weight: 0.5, threshold: 30 }, // Days since creation
        noTrustlines: { weight: 0.7, threshold: 5 }, // Few trustlines is a risk
        suspicious_name: { weight: 0.4, flags: ['safe', 'moon', 'elon', 'doge', 'shib', 'inu', 'swap'] }
    },
    // Wallet risk factors
    wallet: {
        lowActivity: { weight: 0.3, threshold: 10 }, // Few transactions
        highTurnover: { weight: 0.6, threshold: 90 }, // % of funds quickly moved through
        newAccount: { weight: 0.4, threshold: 30 }, // Days since creation
        knownScammer: { weight: 1.0 }, // Known scam addresses
        manyIssuances: { weight: 0.5, threshold: 3 }, // Number of token issuances
        ringTrading: { weight: 0.9 }, // Circular trading pattern
        clusteredTransactions: { weight: 0.7 } // Many transactions in short time
    },
    // Transaction risk factors
    transaction: {
        largeAmount: { weight: 0.5, threshold: 10000 }, // In XRP value
        oddAmount: { weight: 0.4 }, // Strange numbers/patterns
        memoFlags: { weight: 0.6 }, // Suspicious memo flags
        suspiciousPattern: { weight: 0.7 } // Pattern matching known scams
    }
};

// Known high-risk addresses
export const HIGH_RISK_ADDRESSES = [
    // Example list - in production this would be loaded from a database
    'rHYTJDFrbCU1i2yCENTSEgVFJUMWuFqeQj',
    'rG5Ro9e3uGEZVCpwYbLe21nVwXXCGXPkTu',
    'rLpq5RcRzA8FU1yUqEPW4xfsdwon7caQfM',
    // Additional high-risk addresses
    'r3XhydxYWps8EP6xzqs7dEU4DXMjBme95p', // Tag: 74920348
    'rNxp4h8apvRis6mJf9Sh8C6iRxfrDWN7AV', // Tag: 330128380
    'rJMwiqzh3agMG6Hqpa93ycy7GSKtT3EqRW',
    'rnAgPrUpE3sWaNAaFhWdKhTL4uYUw1Cxuz', // Tag: 74920348
    // New addresses from user
    'rNGkUxPVuXQiUV1Qmam2NoXykdvk7KKuGa', // Tag: 2113104184
    'rQjMyVwfvjhfhnYtK4K26M4FHngPceXq3',
    'rMzaEaPx5heMcKgoHeR56xC6DNzxqkeDwt',
    'rEbAAaLMgk58YvNQuV2weyHre6pRwKdKia',
    'rshibopEBREqsfnjERMzn56qvbvZnTScfh',
    'rLWbGeF9B7SwJFb1pnAkwzNL6ehVPhF8xg',
    'rBWpYJhuJWBPAkzJ4kYQqHShSkkF3rgeD', // Tag: 812430925
    'rsjzmZ4WfonC3pXS52zoCxTYfqfiBgCis1', // Tag: 482440097
    'rDCuukSk6NQuFEwFXR5vqVkJrQNezS9cZk',
    'rfa5HrDzTUe3g3UVYQE9y5hgLTRtcrZJvM',
    'rpNF4938Y8zCrqFP2owDHjMUdpAxMs49JD', // Tag: 1241538349
    'raCWHpJj1FgvtpFZQjFxc5C4FyQ6PAAGrN'
];

// Validators for input validation
export const VALIDATORS = {
    address: /^r[A-Za-z0-9]{24,34}$/,
    currency: /^[A-Za-z0-9]{3,40}$/,
    hash: /^[A-F0-9]{64}$/,
    sequence: /^\d+$/
};

// Default analysis settings
export const ANALYSIS_DEFAULTS = {
    maxDepth: 2,
    maxNodes: 100,
    minValue: 20,
    maxConnections: 50,
    networkTimeout: 30000
}; 