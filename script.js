document.addEventListener('DOMContentLoaded', function() {
    // Security enhancement to prevent code leakage in browser console
    const originalConsoleLog = console.log;
    const originalConsoleError = console.error;
    const originalConsoleWarn = console.warn;
    
    // Replace console methods with filtered versions
    console.log = function() {
        const sanitizedArgs = Array.from(arguments).map(arg => sanitizeLogOutput(arg));
        originalConsoleLog.apply(console, sanitizedArgs);
    };
    
    console.error = function() {
        const sanitizedArgs = Array.from(arguments).map(arg => sanitizeLogOutput(arg));
        originalConsoleError.apply(console, sanitizedArgs);
    };
    
    console.warn = function() {
        const sanitizedArgs = Array.from(arguments).map(arg => sanitizeLogOutput(arg));
        originalConsoleWarn.apply(console, sanitizedArgs);
    };
    
    // Function to sanitize sensitive data from logs
    function sanitizeLogOutput(arg) {
        if (typeof arg === 'string') {
            // Sanitize potentially sensitive wallet addresses
            if (arg.match(/r[A-Za-z0-9]{24,34}/)) {
                return arg.replace(/r[A-Za-z0-9]{24,34}/g, (match) => {
                    return match.substring(0, 6) + '...' + match.substring(match.length - 4);
                });
            }
            
            // Sanitize potentially sensitive config information
            if (arg.includes('config') || arg.includes('API_KEY') || arg.includes('password')) {
                return '[REDACTED SENSITIVE DATA]';
            }
        } else if (typeof arg === 'object' && arg !== null) {
            try {
                // Deep copy to avoid modifying original objects
                const copy = JSON.parse(JSON.stringify(arg));
                
                // Sanitize objects that may contain sensitive data
                if (copy.config || copy.API_KEY || copy.password || copy.privateKey) {
                    return { type: typeof arg, message: '[REDACTED SENSITIVE DATA]' };
                }
                
                // Sanitize wallet addresses in objects
                const sanitized = sanitizeObjectAddresses(copy);
                return sanitized;
            } catch (e) {
                // If we can't process this object, better to be safe
                return { type: typeof arg, message: '[OBJECT CANNOT BE SAFELY DISPLAYED]' };
            }
        }
        
        return arg;
    }
    
    // Recursively sanitize all wallet addresses in an object
    function sanitizeObjectAddresses(obj) {
        if (!obj) return obj;
        
        Object.keys(obj).forEach(key => {
            if (typeof obj[key] === 'string' && obj[key].match(/r[A-Za-z0-9]{24,34}/)) {
                obj[key] = obj[key].replace(/r[A-Za-z0-9]{24,34}/g, (match) => {
                    return match.substring(0, 6) + '...' + match.substring(match.length - 4);
                });
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                obj[key] = sanitizeObjectAddresses(obj[key]);
            }
        });
        
        return obj;
    }
    
    // Import our services
    import('./xrpl-service.js').then(module => {
        const xrplService = module.default;
        
        // Import the network analyzer
        import('./network-analyzer.js').then(analyzerModule => {
            const networkAnalyzer = analyzerModule.default;
            
            // Load configuration
            loadConfig().then(config => {
                // Store config for later use
                window.rugCheckerConfig = config;
                
                // Initialize the application with real XRPL connectivity
                initializeApp(xrplService, networkAnalyzer);
            }).catch(error => {
                console.error('Error loading configuration:', error);
                // Continue with default config
                window.rugCheckerConfig = {
                    rcxrpIssuerAddress: 'rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                    tokenGateEnabled: false,
                    maxAnalysisDepth: 3
                };
                initializeApp(xrplService, networkAnalyzer);
            });
            
        }).catch(error => {
            console.error('Error loading network analyzer:', error);
        });
    }).catch(error => {
        console.error('Error loading XRPL service:', error);
        // Fall back to mock data if XRPL service can't be loaded
        initializeAppWithMockData();
    });
});

// Function to load configuration
async function loadConfig() {
    try {
        // In a real application, this would load from a server endpoint
        // that safely exposes .env variables the client needs
        // For this demo, we'll use default values
        
        return {
            rcxrpIssuerAddress: 'rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
            tokenGateEnabled: false,
            maxAnalysisDepth: 3
        };
    } catch (error) {
        console.error('Error loading configuration:', error);
        throw error;
    }
}

// Function to initialize the app with real XRPL connectivity
async function initializeApp(xrplService, networkAnalyzer) {
    // DOM elements
    const walletInput = document.getElementById('wallet-address');
    const scanButton = document.getElementById('scan-button');
    const networkViz = document.getElementById('network-visualization');
    const scanResults = document.getElementById('scan-results');
    const riskScore = document.getElementById('risk-score');
    const connectedWallets = document.getElementById('connected-wallets');
    const connectedTokens = document.getElementById('connected-tokens');

    // Add forest pattern to the analyzer section
    const analyzerSection = document.getElementById('analyzer');
    const forestPattern = document.createElement('div');
    forestPattern.className = 'forest-pattern';
    if (analyzerSection && !document.querySelector('.forest-pattern')) {
        analyzerSection.appendChild(forestPattern);
    }

    // XRPL Network visualization setup
    let viz = null;
    let simulation = null;
    
    // Try to connect to XRPL network
    try {
        await xrplService.connect();
        console.log('Connected to XRPL network:', xrplService.connectionStatus);
    } catch (error) {
        console.error('Failed to connect to XRPL network:', error);
    }
    
    // Initialize the visualization with placeholder data
    initVisualization();
    
    // Event listeners
    scanButton.addEventListener('click', performScan);
    
    // Function to initialize the visualization with placeholder data
    function initVisualization() {
        // Clear any existing visualization
        if (networkViz) {
            networkViz.innerHTML = '';
        }
        
        // Set up the visualization using D3.js
        const width = networkViz.clientWidth;
        const height = networkViz.clientHeight;
        
        // Create SVG element
        const svg = d3.select('#network-visualization')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
            
        // Add a background pattern for the forest green theme
        svg.append('rect')
            .attr('width', width)
            .attr('height', height)
            .attr('fill', '#121212');
        
        // Add a subtle grid pattern
        const defs = svg.append('defs');
        
        // Create pattern for the grid
        const pattern = defs.append('pattern')
            .attr('id', 'grid')
            .attr('width', 30)
            .attr('height', 30)
            .attr('patternUnits', 'userSpaceOnUse');
            
        pattern.append('rect')
            .attr('width', 30)
            .attr('height', 30)
            .attr('fill', 'none');
            
        pattern.append('circle')
            .attr('cx', 15)
            .attr('cy', 15)
            .attr('r', 1)
            .attr('fill', 'rgba(105, 240, 174, 0.1)');
            
        // Apply the pattern
        svg.append('rect')
            .attr('width', width)
            .attr('height', height)
            .attr('fill', 'url(#grid)');
            
        // Add title for placeholder
        svg.append('text')
            .attr('x', width / 2)
            .attr('y', height / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', '#69f0ae')
            .style('font-size', '18px')
            .text('Enter a valid XRPL wallet address to visualize connections');
            
        // Add the RugCheckerX watermark
        svg.append('text')
            .attr('x', width / 2)
            .attr('y', height - 20)
            .attr('text-anchor', 'middle')
            .attr('fill', 'rgba(105, 240, 174, 0.2)')
            .style('font-size', '24px')
            .text('RugCheckerX');
            
        // Add decorative elements
        addDecorativeElements(svg, width, height);
    }
    
    // Add decorative elements to the visualization
    function addDecorativeElements(svg, width, height) {
        // Add decorative corner elements in forest green theme
        const cornerSize = 50;
        
        // Top-left corner
        svg.append('path')
            .attr('d', `M0,0 L${cornerSize},0 L0,${cornerSize} Z`)
            .attr('fill', 'rgba(27, 94, 32, 0.2)');
            
        // Top-right corner
        svg.append('path')
            .attr('d', `M${width},0 L${width-cornerSize},0 L${width},${cornerSize} Z`)
            .attr('fill', 'rgba(27, 94, 32, 0.2)');
            
        // Bottom-left corner
        svg.append('path')
            .attr('d', `M0,${height} L${cornerSize},${height} L0,${height-cornerSize} Z`)
            .attr('fill', 'rgba(27, 94, 32, 0.2)');
            
        // Bottom-right corner
        svg.append('path')
            .attr('d', `M${width},${height} L${width-cornerSize},${height} L${width},${height-cornerSize} Z`)
            .attr('fill', 'rgba(27, 94, 32, 0.2)');
    }
    
    // Function to perform the wallet scan
    async function performScan() {
        const walletAddress = walletInput.value.trim();
        
        if (!walletAddress) {
            alert('Please enter a valid XRPL wallet address or token ID');
            return;
        }

        // Validate the wallet address
        if (!xrplService.isValidAddress(walletAddress)) {
            alert('Invalid XRPL wallet address format');
            return;
        }
        
        // Show loading state with progress bar in results area
        scanResults.innerHTML = `
            <div class="loading-container">
                <p class="loading">Scanning XRPL network and analyzing wallet connections...</p>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="scan-progress-bar"></div>
                    <div class="progress-percentage" id="scan-progress-percentage">0%</div>
                </div>
                <div class="progress-info">This may take a minute to gather comprehensive network data</div>
            </div>
        `;
        
        // Also show a loading overlay in the visualization area
        networkViz.innerHTML = `
            <div class="loading-overlay">
                <p class="loading">Analyzing network connections...</p>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="viz-progress-bar"></div>
                    <div class="progress-percentage" id="viz-progress-percentage">0%</div>
                </div>
            </div>
        `;
        
        // Animate progress bars
        const progressBar = document.getElementById('scan-progress-bar');
        const vizProgressBar = document.getElementById('viz-progress-bar');
        const progressPercentage = document.getElementById('scan-progress-percentage');
        const vizProgressPercentage = document.getElementById('viz-progress-percentage');
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 1;
            if (progress > 95) {
                clearInterval(progressInterval);
            } else {
                progressBar.style.width = progress + '%';
                vizProgressBar.style.width = progress + '%';
                progressPercentage.textContent = progress + '%';
                vizProgressPercentage.textContent = progress + '%';
            }
        }, 200);
        
        try {
            // Get the RCXRP issuer address from config
            const rcxrpIssuerAddress = window.rugCheckerConfig?.rcxrpIssuerAddress || 'rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
            
            // Get max analysis depth from config
            const configMaxDepth = window.rugCheckerConfig?.maxAnalysisDepth || 3;
            
            let data;
            
            if (walletAddress === rcxrpIssuerAddress) {
                // If this is the RCXRP issuer, show special display without tokens
                data = await networkAnalyzer.analyzeNetwork(walletAddress, configMaxDepth);
                
                // Override the nodes to remove any tokens
                data.nodes = data.nodes.filter(node => node.type !== 'token');
                
                // Remove any links to tokens
                data.links = data.links.filter(link => {
                    const sourceNode = data.nodes.find(n => n.id === link.source);
                    const targetNode = data.nodes.find(n => n.id === link.target);
                    return sourceNode && targetNode;
                });
                
                // Override metrics
                networkAnalyzer.metrics.connectedTokens = 0;
            } else {
                // Perform network analysis with configured depth
                data = await networkAnalyzer.analyzeNetwork(walletAddress, configMaxDepth);
            }
            
            // Complete progress bar
            clearInterval(progressInterval);
            if (progressBar) progressBar.style.width = '100%';
            if (vizProgressBar) vizProgressBar.style.width = '100%';
            if (progressPercentage) progressPercentage.textContent = '100%';
            if (vizProgressPercentage) vizProgressPercentage.textContent = '100%';
            
            // Update visualization with real data
            updateVisualization(data);
            
            // Update metrics from the analysis
            const metrics = networkAnalyzer.getMetrics();
            updateMetrics(metrics);
            
            // Display results from the analysis
            const findings = networkAnalyzer.getFindings();
            displayResults(data, findings);
            
            // Add help text for interactivity
            const helpText = document.createElement('div');
            helpText.className = 'help-text';
            helpText.innerHTML = '<strong>Interactive Controls:</strong><br>• Scroll to zoom in/out<br>• Click nodes for details<br>• Drag nodes to reposition';
            networkViz.appendChild(helpText);
            
            // Keep help text visible permanently (remove the auto-hide)
            // setTimeout(() => {
            //     helpText.style.opacity = '0';
            //     setTimeout(() => helpText.remove(), 1000);
            // }, 7000);
            
        } catch (error) {
            // Stop progress animation on error
            clearInterval(progressInterval);
            
            console.error('Error performing scan:', error);
            scanResults.innerHTML = `<p class="error">Error performing scan: ${error.message}</p>`;
            networkViz.innerHTML = `<p class="error" style="padding: 20px; text-align: center;">Error visualizing network: ${error.message}</p>`;
        }
    }
    
    // Function to update metrics display
    function updateMetrics(metrics) {
        riskScore.textContent = metrics.riskScore;
        connectedWallets.textContent = metrics.connectedWallets;
        connectedTokens.textContent = metrics.connectedTokens;
        
        // Update risk score color
        if (metrics.riskScore > 70) {
            riskScore.style.color = '#ff5252'; // Red for high risk
            
            // Highlight the high risk category
            document.querySelectorAll('.risk-level').forEach(el => el.classList.remove('active'));
            document.querySelector('.risk-level.high-risk').classList.add('active');
        } else if (metrics.riskScore > 30) {
            riskScore.style.color = '#ffeb3b'; // Yellow for medium risk
            
            // Highlight the medium risk category
            document.querySelectorAll('.risk-level').forEach(el => el.classList.remove('active'));
            document.querySelector('.risk-level.medium-risk').classList.add('active');
        } else {
            riskScore.style.color = '#69f0ae'; // Green for low risk
            
            // Highlight the low risk category
            document.querySelectorAll('.risk-level').forEach(el => el.classList.remove('active'));
            document.querySelector('.risk-level.low-risk').classList.add('active');
        }
    }
    
    // Function to display detailed results
    function displayResults(data, findings) {
        const metrics = networkAnalyzer.getMetrics();
        
        let resultsHTML = `
            <div class="result-summary">
                <h4>Security Analysis for ${shortenAddress(data.mainNode)}</h4>
                <div class="risk-indicator ${getRiskClass(metrics.riskScore)}">
                    <span class="risk-value">${metrics.riskScore}%</span>
                    <span class="risk-label">Risk Score</span>
                </div>
            </div>
            <div class="result-details">
                <h4>Findings</h4>
                <ul class="findings-list">
        `;
        
        // Add findings based on the analysis
        findings.forEach(finding => {
            resultsHTML += `
                <li class="finding-item ${finding.severity}">
                    <span class="finding-icon">${getSeverityIcon(finding.severity)}</span>
                    <div class="finding-content">
                        <h5>${finding.title}</h5>
                        <p>${finding.description}</p>
                    </div>
                </li>
            `;
        });
        
        resultsHTML += `
                </ul>
            </div>
            <div class="token-analysis">
                <h4>Token Analysis</h4>
                <div class="token-list">
        `;
        
        // Add token analysis
        data.nodes.filter(node => node.type === 'token').forEach(token => {
            resultsHTML += `
                <div class="token-item">
                    <div class="token-header">
                        <span class="token-name">${convertHexToString(token.name) || token.name}</span>
                        <span class="token-risk ${getRiskClass(token.riskLevel * 10)}">${Math.round(token.riskLevel * 10)}% Risk</span>
                    </div>
                    <div class="token-details">
                        <p>${token.description || convertHexToString(token.name) + ' token issued by ' + shortenAddress(token.issuer)}</p>
                        <p class="token-metadata">Issued: ${formatDate(token.issueDate) || 'Unknown'} | Holders: ${formatNumberWithCommas(token.holders)}</p>
                    </div>
                </div>
            `;
        });
        
        resultsHTML += `
                </div>
            </div>
        `;
        
        // Add real-time transaction section
        resultsHTML += `
            <div class="transaction-history">
                <h4>Transaction History</h4>
                <p>Analyze the transaction history to identify suspicious patterns.</p>
                <div class="transaction-actions">
                    <button class="btn transaction-btn" id="view-transactions">View Transactions</button>
                    <button class="btn transaction-btn" id="check-trustlines">Check Trustlines</button>
                </div>
            </div>
        `;
        
        scanResults.innerHTML = resultsHTML;
        
        // Add event listeners for the new buttons
        document.getElementById('view-transactions').addEventListener('click', () => {
            viewTransactionHistory(data.mainNode);
        });
        
        document.getElementById('check-trustlines').addEventListener('click', () => {
            checkTrustlines(data.mainNode);
        });
    }
    
    // Helper function to shorten wallet address
    function shortenAddress(address) {
        if (!address || address.length < 10) return address;
        return `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
    }
    
    // Helper function to get severity icon
    function getSeverityIcon(severity) {
        switch (severity) {
            case 'high': return '⚠️';
            case 'medium': return '⚠';
            case 'low': return 'ℹ️';
            default: return '•';
        }
    }
    
    // Function to view transaction history
    async function viewTransactionHistory(address) {
        try {
            // Show loading state
            scanResults.innerHTML += '<p class="loading">Loading transaction history...</p>';
            
            // Fetch transaction history
            const transactions = await xrplService.getAccountTransactions(address);
            
            // Display transaction history
            let txHTML = `
                <div class="transaction-history-detail">
                    <h4>Transaction History for ${shortenAddress(address)}</h4>
                    <table class="transaction-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Destination</th>
                                <th>Amount</th>
                                <th>Date</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            transactions.slice(0, 10).forEach(tx => {
                txHTML += `
                    <tr>
                        <td>${tx.TransactionType || 'Unknown'}</td>
                        <td>${tx.Destination ? shortenAddress(tx.Destination) : 'N/A'}</td>
                        <td>${formatAmount(tx.Amount)}</td>
                        <td>${formatDate(tx.date)}</td>
                        <td>${tx.status || 'Success'}</td>
                    </tr>
                `;
            });
            
            txHTML += `
                        </tbody>
                    </table>
                </div>
            `;
            
            // Replace loading message with transaction history
            scanResults.innerHTML = scanResults.innerHTML.replace('<p class="loading">Loading transaction history...</p>', txHTML);
        } catch (error) {
            console.error('Error fetching transaction history:', error);
            scanResults.innerHTML = scanResults.innerHTML.replace(
                '<p class="loading">Loading transaction history...</p>', 
                `<p class="error">Error fetching transaction history: ${error.message}</p>`
            );
        }
    }
    
    // Function to check trustlines
    async function checkTrustlines(address) {
        try {
            // Show loading state
            scanResults.innerHTML += '<p class="loading">Loading trustlines...</p>';
            
            // Fetch account balances which include trustlines
            const balances = await xrplService.getAccountBalances(address);
            
            // Display trustlines
            let trustHTML = `
                <div class="trustlines-detail">
                    <h4>Trustlines for ${shortenAddress(address)}</h4>
                    <table class="trustlines-table">
                        <thead>
                            <tr>
                                <th>Currency</th>
                                <th>Issuer</th>
                                <th>Balance</th>
                                <th>Limit</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            if (balances.tokens && balances.tokens.length > 0) {
                balances.tokens.forEach(token => {
                    trustHTML += `
                        <tr>
                            <td>${token.currency || 'Unknown'}</td>
                            <td>${token.issuer ? shortenAddress(token.issuer) : 'N/A'}</td>
                            <td>${token.value || '0'}</td>
                            <td>${token.limit || 'No Limit'}</td>
                        </tr>
                    `;
                });
            } else {
                trustHTML += `
                    <tr>
                        <td colspan="4">No trustlines found</td>
                    </tr>
                `;
            }
            
            trustHTML += `
                        </tbody>
                    </table>
                </div>
            `;
            
            // Replace loading message with trustlines
            scanResults.innerHTML = scanResults.innerHTML.replace('<p class="loading">Loading trustlines...</p>', trustHTML);
        } catch (error) {
            console.error('Error fetching trustlines:', error);
            scanResults.innerHTML = scanResults.innerHTML.replace(
                '<p class="loading">Loading trustlines...</p>', 
                `<p class="error">Error fetching trustlines: ${error.message}</p>`
            );
        }
    }
    
    // Helper function to get risk class
    function getRiskClass(score) {
        if (score > 70) return 'high-risk';
        if (score > 30) return 'medium-risk';
        return 'low-risk';
    }
    
    // Helper function to format amount
    function formatAmount(amount) {
        if (!amount) return 'N/A';
        if (typeof amount === 'string') return amount;
        if (amount.currency) return `${amount.value} ${amount.currency}`;
        return amount.toString();
    }
    
    // Helper function to format date
    function formatDate(dateStr) {
        if (!dateStr) return 'Unknown';
        
        let date;
        // Check if it's an epoch timestamp in seconds or milliseconds
        if (typeof dateStr === 'number' || !isNaN(Number(dateStr))) {
            // If the timestamp is in seconds (UNIX format), convert to milliseconds
            const timestamp = Number(dateStr);
            date = new Date(timestamp < 10000000000 ? timestamp * 1000 : timestamp);
        } else {
            date = new Date(dateStr);
        }
        
        // Check if date is valid
        if (isNaN(date.getTime())) {
            return 'Invalid Date';
        }
        
        // Check if date is near Unix epoch (suggesting a wrong date format)
        if (date.getFullYear() < 2000) {
            // Use current date as fallback for very old dates that are likely wrong
            date = new Date();
        }
        
        // Return formatted date - just the date without time
        return date.toLocaleDateString();
    }
    
    // Define gradient patterns for different node types
    function defineGradients(defs) {
        // Main wallet gradient (green)
        const greenGradient = defs.append('linearGradient')
            .attr('id', 'greenGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        greenGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#4c8c4a');
            
        greenGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#003300');
        
        // Token gradient (orange)
        const tokenGradient = defs.append('linearGradient')
            .attr('id', 'tokenGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        tokenGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#ff9800');
            
        tokenGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#e65100');
        
        // Early participant gradient (blue)
        const earlyGradient = defs.append('linearGradient')
            .attr('id', 'earlyGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        earlyGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#2196f3');
            
        earlyGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#0d47a1');
        
        // High risk wallet gradient (red)
        const riskGradient = defs.append('linearGradient')
            .attr('id', 'riskGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        riskGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#ff5252');
            
        riskGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#b71c1c');

        // Medium risk wallet gradient (yellow-orange)
        const mediumRiskGradient = defs.append('linearGradient')
            .attr('id', 'mediumRiskGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        mediumRiskGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#ffeb3b');
            
        mediumRiskGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#f57f17');

        // Low risk wallet gradient (green-blue)
        const lowRiskGradient = defs.append('linearGradient')
            .attr('id', 'lowRiskGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        lowRiskGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#69f0ae');
            
        lowRiskGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#00796b');
            
        // Early participant with high risk (purple-red)
        const earlyHighRiskGradient = defs.append('linearGradient')
            .attr('id', 'earlyHighRiskGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        earlyHighRiskGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#9c27b0');
            
        earlyHighRiskGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#b71c1c');
            
        // Early participant with medium risk (blue-yellow)
        const earlyMediumRiskGradient = defs.append('linearGradient')
            .attr('id', 'earlyMediumRiskGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '100%')
            .attr('y2', '100%');
            
        earlyMediumRiskGradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#2196f3');
            
        earlyMediumRiskGradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#f57f17');
            
        // Define a glow filter for high risk nodes
        const highRiskGlow = defs.append('filter')
            .attr('id', 'highRiskGlow')
            .attr('x', '-50%')
            .attr('y', '-50%')
            .attr('width', '200%')
            .attr('height', '200%');
            
        highRiskGlow.append('feGaussianBlur')
            .attr('stdDeviation', '3.5')
            .attr('result', 'coloredBlur');
            
        const femergeHighRisk = highRiskGlow.append('feMerge');
        femergeHighRisk.append('feMergeNode')
            .attr('in', 'coloredBlur');
        femergeHighRisk.append('feMergeNode')
            .attr('in', 'SourceGraphic');
    }
    
    // Get node fill based on node type and properties
    function getNodeFill(d, mainNodeId) {
        if (d.id === mainNodeId) return 'url(#greenGradient)';
        if (d.type === 'token') return 'url(#tokenGradient)';
        
        // Early participants with risk levels
        if (d.earlyParticipant) {
            if (d.riskLevel > 0.7) return 'url(#earlyHighRiskGradient)';
            if (d.riskLevel > 0.4) return 'url(#earlyMediumRiskGradient)';
            return 'url(#earlyGradient)';
        }
        
        // Enhanced risk level visualization using more distinctive gradients
        if (d.riskLevel > 0.7) return 'url(#riskGradient)';
        if (d.riskLevel > 0.4) return 'url(#mediumRiskGradient)';
        return 'url(#lowRiskGradient)';
    }

    // Get node stroke based on node type
    function getNodeStroke(d, mainNodeId) {
        if (d.id === mainNodeId) return '#ffffff';
        if (d.type === 'token') return 'rgba(255, 255, 255, 0.7)';
        
        // Enhanced stroke colors for early participants
        if (d.earlyParticipant) {
            if (d.riskLevel > 0.7) return '#ff1744'; // Bright red for high risk early participants
            if (d.riskLevel > 0.4) return '#ffea00'; // Bright yellow for medium risk early participants
            return '#00b0ff'; // Default blue for low risk early participants
        }

        // Enhanced stroke colors based on risk
        if (d.riskLevel > 0.7) return '#ff5252';
        if (d.riskLevel > 0.4) return '#ffeb3b';
        return '#69f0ae';
    }

    // Get node stroke width
    function getNodeStrokeWidth(d, mainNodeId) {
        if (d.id === mainNodeId) return 3;
        if (d.earlyParticipant && d.riskLevel > 0.7) return 3; // Thicker border for high risk early participants
        if (d.earlyParticipant) return 2;
        // Add thicker border for high risk wallets
        if (d.riskLevel > 0.7) return 2;
        return 1;
    }

    // Get node filter (glow effect)
    function getNodeFilter(d, mainNodeId) {
        if (d.id === mainNodeId) return 'url(#glow)';
        // Add glow to high risk nodes
        if (d.riskLevel > 0.7) return 'url(#highRiskGlow)';
        return '';
    }

    // Get label text based on node type
    function getLabelText(d) {
        if (d.type === 'token') {
            // Convert hex to readable name if needed
            return convertHexToString(d.name);
        }
        return shortenAddress(d.id);
    }

    // Get connected tokens for a wallet
    function getConnectedTokens(walletId, data) {
        const tokenLinks = data.links.filter(link => 
            (link.source.id === walletId && link.target.type === 'token') || 
            (link.target.id === walletId && link.source.type === 'token')
        );
        
        const connectedTokens = tokenLinks.map(link => 
            link.source.type === 'token' ? link.source : link.target
        );
        
        return connectedTokens;
    }

    // Convert hex format to readable string
    function convertHexToString(hexStr) {
        // If the string already looks like a readable name, return it
        if (!hexStr || !hexStr.startsWith('0x') && !/^[0-9A-F]+$/i.test(hexStr)) {
            return hexStr;
        }
        
        try {
            // Remove 0x prefix if present
            hexStr = hexStr.replace(/^0x/, '');
            
            // Convert hex to string
            let result = '';
            for (let i = 0; i < hexStr.length; i += 2) {
                const hexChar = hexStr.substr(i, 2);
                const decimal = parseInt(hexChar, 16);
                // Only include printable ASCII characters
                if (decimal >= 32 && decimal <= 126) {
                    result += String.fromCharCode(decimal);
                }
            }
            
            // Trim any null characters that might be padding
            result = result.replace(/\0/g, '').replace(/\u0000/g, '').trim();
            
            return result || hexStr;
        } catch (e) {
            console.error('Error converting hex to string:', e);
            return hexStr;
        }
    }
    
    // Function to update the visualization with network data
    function updateVisualization(data) {
        console.log('Updating visualization with data:', data);
        
        // Clear existing visualization
        networkViz.innerHTML = '';
        
        // Get dimensions
        const width = networkViz.clientWidth;
        const height = networkViz.clientHeight;
        
        // Make a deep copy to avoid modifying original data
        const workingData = JSON.parse(JSON.stringify(data));
        
        // Create SVG element
        const svg = d3.select('#network-visualization')
            .append('svg')
            .attr('width', width)
            .attr('height', height)
            .call(d3.zoom()
                .scaleExtent([0.1, 8])
                .on("zoom", function(event) {
                    vizGroup.attr("transform", event.transform);
                }));
        
        // Add a background rect to handle zoom events
        svg.append('rect')
            .attr('width', width)
            .attr('height', height)
            .attr('fill', '#121212');
        
        // Define the forest green gradient
        const defs = svg.append('defs');
        
        // Create pattern for the grid
        const pattern = defs.append('pattern')
            .attr('id', 'grid')
            .attr('width', 30)
            .attr('height', 30)
            .attr('patternUnits', 'userSpaceOnUse');
            
        pattern.append('rect')
            .attr('width', 30)
            .attr('height', 30)
            .attr('fill', 'none');
            
        pattern.append('circle')
            .attr('cx', 15)
            .attr('cy', 15)
            .attr('r', 1)
            .attr('fill', 'rgba(105, 240, 174, 0.1)');
            
        // Apply the pattern
        svg.append('rect')
            .attr('width', width)
            .attr('height', height)
            .attr('fill', 'url(#grid)');
        
        // Define gradients for different node types
        defineGradients(defs);
        
        // Define glow effect
        const glow = defs.append('filter')
            .attr('id', 'glow')
            .attr('x', '-50%')
            .attr('y', '-50%')
            .attr('width', '200%')
            .attr('height', '200%');
            
        glow.append('feGaussianBlur')
            .attr('stdDeviation', '2.5')
            .attr('result', 'coloredBlur');
            
        const femerge = glow.append('feMerge');
        femerge.append('feMergeNode')
            .attr('in', 'coloredBlur');
        femerge.append('feMergeNode')
            .attr('in', 'SourceGraphic');
        
        // Add decorative elements
        addDecorativeElements(svg, width, height);
        
        // Create a group for zoom/pan transformation
        const vizGroup = svg.append("g")
            .attr("class", "viz-group");
        
        // Prepare nodes array for D3 (convert links to use objects not strings)
        // This is the critical fix - we need to convert link source/target from strings to references
        const nodeMap = {};
        workingData.nodes.forEach(node => {
            // Assign initial positions to prevent nodes from starting at the same point
            // This helps prevent initial force explosion and improves layout
            node.x = width / 2 + (Math.random() - 0.5) * 100;
            node.y = height / 2 + (Math.random() - 0.5) * 100;
            nodeMap[node.id] = node;
        });
        
        // Convert links to use references instead of strings
        workingData.links.forEach(link => {
            link.source = nodeMap[link.source] || link.source;
            link.target = nodeMap[link.target] || link.target;
        });
        
        // Create force simulation with more forces for better distribution
        simulation = d3.forceSimulation(workingData.nodes)
            .force('link', d3.forceLink(workingData.links)
                .id(d => d.id)
                .distance(d => {
                    // Use much larger distances for better spacing
                    if (d.source.type === 'token' || d.target.type === 'token') return 180;
                    if (d.earlyTransaction) return 150; // Keep early transaction connections closer
                    if (d.highRiskConnection) return 200; // Separate high-risk connections more
                    if (d.relatedConnection) return 170; // Medium distance for related wallets
                    return 160; // Larger default distance
                })
                .strength(d => {
                    // Adjust link strength based on node types and properties
                    if (d.source.id === workingData.mainNode || d.target.id === workingData.mainNode) {
                        return 0.5; // Weaker pull towards main node for better spread
                    }
                    if (d.source.type === 'token' || d.target.type === 'token') {
                        return 0.4; // Weaker strength for token connections
                    }
                    if (d.earlyParticipant) {
                        return 0.4; // Weaker for early participants
                    }
                    if (d.highRiskConnection) {
                        return 0.6; // Stronger for high-risk connections
                    }
                    return 0.3; // Weaker default strength for better spreading
                }))
            .force('charge', d3.forceManyBody()
                .strength(d => {
                    // Increase repulsion force for better distribution
                    if (d.id === workingData.mainNode) return -800; // Stronger repulsion for main node
                    if (d.type === 'token') return -500; // Strong repulsion for tokens
                    if (d.isHighRisk) return -400; // Strong repulsion for high-risk wallets
                    return -300; // Stronger repulsion for other nodes
                })
                .distanceMax(350)) // Limit the distance effect of repulsion
            .force('center', d3.forceCenter(width / 2, height / 2).strength(0.05))
            .force('collide', d3.forceCollide()
                .radius(d => d.radius * 2.5) // Much larger collision radius to prevent overlap
                .strength(0.8))
            .force('x', d3.forceX(width / 2).strength(d => {
                // Custom strength to keep nodes centered on x-axis but allow more freedom
                if (d.id === workingData.mainNode) return 0.1; // Stronger for main node
                if (d.type === 'token') return 0.02; // Weaker for tokens
                return 0.04; // Weaker for all other nodes
            }))
            .force('y', d3.forceY(height / 2).strength(d => {
                // Custom strength to keep nodes centered on y-axis but allow more freedom
                if (d.id === workingData.mainNode) return 0.1; // Stronger for main node
                if (d.type === 'token') return 0.02; // Weaker for tokens
                return 0.04; // Weaker for all other nodes
            }))
            // Add radial force to distribute nodes in rings around center
            .force('radial', d3.forceRadial(d => {
                // Determine radius based on node type and connections
                if (d.id === workingData.mainNode) return 0; // Center node at origin
                if (d.isHighRisk) return Math.min(width, height) * 0.4; // High-risk in middle ring
                if (d.type === 'token') return Math.min(width, height) * 0.3; // Tokens closer to center
                if (d.earlyParticipant) return Math.min(width, height) * 0.35; // Early participants in middle
                return Math.min(width, height) * 0.45; // Other nodes pushed outward
            }, width / 2, height / 2).strength(0.3))
            .alpha(1)    // Start with maximum alpha for better initial arrangement
            .alphaDecay(0.01); // Slower decay for more gradual settling

        // Define drag handler functions within the updateVisualization scope
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
            
            // For main node dragging, apply some pull to connected nodes for better coordination
            if (d.id === workingData.mainNode) {
                // Find directly connected nodes
                const connectedNodes = workingData.links
                    .filter(link => link.source.id === d.id || link.target.id === d.id)
                    .map(link => link.source.id === d.id ? link.target : link.source);
                
                // Apply a slight pull to connected nodes
                connectedNodes.forEach(node => {
                    const dx = d.x - node.x;
                    const dy = d.y - node.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    // Only apply to nearby nodes
                    if (distance < 200) {
                        const pull = 0.1; // Strength of pull
                        node.x += dx * pull;
                        node.y += dy * pull;
                    }
                });
            }
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            // Keep position fixed where user dragged it (don't reset fx/fy)
            // d.fx = null;
            // d.fy = null;
        }
        
        // Create a drag handler with the defined functions
        const dragHandler = d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended);
        
        // Create link groups for different types of connections
        const linkGroups = {
            earlyTxn: vizGroup.append('g').attr('class', 'links early-txn-links'),
            token: vizGroup.append('g').attr('class', 'links token-links'),
            suspicious: vizGroup.append('g').attr('class', 'links suspicious-links'),
            regular: vizGroup.append('g').attr('class', 'links regular-links')
        };
        
        // Process links by type
        const earlyTxnLinks = workingData.links.filter(link => link.earlyTransaction);
        const tokenLinks = workingData.links.filter(link => 
            (link.source.type === 'token' || link.target.type === 'token') && !link.earlyTransaction);
        const suspiciousLinks = workingData.links.filter(link => 
            link.suspicious && !link.earlyTransaction && 
            link.source.type !== 'token' && link.target.type !== 'token');
        const regularLinks = workingData.links.filter(link => 
            !link.earlyTransaction && !link.suspicious && 
            link.source.type !== 'token' && link.target.type !== 'token');
        
        // Helper function to create links with specific styles
        function createLinks(group, links, color, widthFactor, opacity) {
            group.selectAll('line')
                .data(links)
                .enter()
                .append('line')
                .attr('stroke', d => d.suspicious ? '#ff5252' : color)
                .attr('stroke-opacity', d => (d.value / 10) * opacity)
                .attr('stroke-width', d => Math.sqrt(d.value) * widthFactor)
                .attr('class', d => d.earlyTransaction ? 'early-transaction' : '');
        }
        
        // Create links with different styles based on category
        createLinks(linkGroups.earlyTxn, earlyTxnLinks, '#ff9800', 1.5, 0.8); // Orange for early transactions
        createLinks(linkGroups.token, tokenLinks, '#69f0ae', 1, 0.6); // Green for token links
        createLinks(linkGroups.suspicious, suspiciousLinks, '#ff5252', 1, 0.7); // Red for suspicious
        createLinks(linkGroups.regular, regularLinks, '#4fc3f7', 1, 0.5); // Blue for regular
        
        // Create nodes
        const node = vizGroup.append('g')
            .attr('class', 'nodes')
            .selectAll('circle')
            .data(workingData.nodes)
            .enter()
            .append('circle')
            .attr('r', d => d.radius)
            .attr('fill', d => getNodeFill(d, workingData.mainNode))
            .attr('stroke', d => getNodeStroke(d, workingData.mainNode))
            .attr('stroke-width', d => getNodeStrokeWidth(d, workingData.mainNode))
            .attr('filter', d => getNodeFilter(d, workingData.mainNode))
            .attr('cursor', 'pointer')
            .attr('id', d => d.id) // Add ID for easier selection
            .attr('class', d => {
                let classes = `node ${d.type}`;
                if (d.earlyParticipant) classes += ' early-participant';
                if (d.riskLevel > 0.7) classes += ' high-risk';
                if (d.suspiciousPatterns && d.suspiciousPatterns.length) classes += ' suspicious';
                return classes;
            })
            .call(dragHandler)
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip)
            .on('click', nodeClicked);
                
        // Add labels
        const label = vizGroup.append('g')
            .attr('class', 'labels')
            .selectAll('text')
            .data(workingData.nodes)
            .enter()
            .append('text')
            .text(d => getLabelText(d))
            .attr('font-size', d => d.id === workingData.mainNode ? '12px' : '10px')
            .attr('fill', '#ffffff')
            .attr('dx', d => d.radius + 5)
            .attr('dy', 4)
            .attr('cursor', 'pointer')
            .on('click', nodeClicked);
            
        // Function to add a legend explaining the network visualization
        function addLegend(svg, width, height) {
            const legendGroup = svg.append('g')
                .attr('class', 'legend')
                .attr('transform', `translate(${width - 240}, ${height - 270})`);
            
            // Add semi-transparent background
            legendGroup.append('rect')
                .attr('width', 220)
                .attr('height', 250)
                .attr('fill', 'rgba(0, 0, 0, 0.7)')
                .attr('rx', 5)
                .attr('ry', 5);
                
            // Add legend title
            legendGroup.append('text')
                .attr('x', 10)
                .attr('y', 20)
                .attr('fill', '#ffffff')
                .attr('font-size', '14px')
                .attr('font-weight', 'bold')
                .text('Legend');
            
            // Create legend items
            const items = [
                { label: 'Main Wallet', color: 'url(#greenGradient)', type: 'circle', radius: 8 },
                { label: 'Connected Wallet (Low Risk)', color: 'url(#lowRiskGradient)', type: 'circle', radius: 6 },
                { label: 'Connected Wallet (Medium Risk)', color: 'url(#mediumRiskGradient)', type: 'circle', radius: 6 },
                { label: 'Connected Wallet (High Risk)', color: 'url(#riskGradient)', type: 'circle', radius: 6, filter: 'url(#highRiskGlow)' },
                { label: 'Early Participant (Low Risk)', color: 'url(#earlyGradient)', type: 'circle', radius: 6 },
                { label: 'Early Participant (Medium Risk)', color: 'url(#earlyMediumRiskGradient)', type: 'circle', radius: 6 },
                { label: 'Early Participant (High Risk)', color: 'url(#earlyHighRiskGradient)', type: 'circle', radius: 6, filter: 'url(#highRiskGlow)' },
                { label: 'Token', color: 'url(#tokenGradient)', type: 'circle', radius: 6 },
                { label: 'Early Transaction', color: '#ff9800', type: 'line', width: 20 },
                { label: 'Suspicious Link', color: '#ff5252', type: 'line', width: 20 }
            ];
            
            // Add each legend item
            items.forEach((item, i) => {
                const y = 40 + (i * 21);
                
                // Add the symbol (circle or line)
                if (item.type === 'circle') {
                    const circle = legendGroup.append('circle')
                        .attr('cx', 20)
                        .attr('cy', y)
                        .attr('r', item.radius)
                        .attr('fill', item.color);
                    
                    // Add filter if specified
                    if (item.filter) {
                        circle.attr('filter', item.filter);
                    }
                } else if (item.type === 'line') {
                    legendGroup.append('line')
                        .attr('x1', 10)
                        .attr('y1', y)
                        .attr('x2', 30)
                        .attr('y2', y)
                        .attr('stroke', item.color)
                        .attr('stroke-width', 2);
                }
                
                // Add the label
                legendGroup.append('text')
                    .attr('x', 40)
                    .attr('y', y + 4)
                    .attr('fill', '#ffffff')
                    .attr('font-size', '12px')
                    .text(item.label);
            });
            
            // Add interactive note
            legendGroup.append('text')
                .attr('x', 10)
                .attr('y', 240)
                .attr('fill', '#aaaaaa')
                .attr('font-size', '10px')
                .text('Tip: Click nodes for details');
        }
        
        // Add a legend to explain the visualization
        addLegend(svg, width, height);
        
        // Cool-down phase to improve initial layout
        // Run the simulation for a few iterations before rendering
        for (let i = 0; i < 30; i++) {
            simulation.tick();
        }
        
        // Apply bounding to keep nodes within view
        function applyBounding() {
            workingData.nodes.forEach(d => {
                // Add padding to keep nodes away from edges
                const padding = d.radius + 5;
                
                // Bound nodes to keep them within the visible area with padding
                d.x = Math.max(padding, Math.min(width - padding, d.x));
                d.y = Math.max(padding, Math.min(height - padding, d.y));
            });
        }
        
        // Apply initial bounding
        applyBounding();
        
        // Update simulation
        simulation.on('tick', () => {
            // Apply bounding on each tick
            applyBounding();
            
            // Update all link positions
            for (const groupKey in linkGroups) {
                linkGroups[groupKey].selectAll('line')
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
            }
                
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
                
            label
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        });
        
        // Create tooltip for nodes with enhanced information
        const tooltip = d3.select('body').append('div')
            .attr('class', 'node-tooltip')
            .style('opacity', 0)
            .style('position', 'absolute')
            .style('background-color', 'rgba(0, 0, 0, 0.9)')
            .style('color', 'white')
            .style('padding', '12px')
            .style('border-radius', '6px')
            .style('pointer-events', 'none')
            .style('max-width', '320px')
            .style('z-index', 1000)
            .style('box-shadow', '0 4px 8px rgba(0, 0, 0, 0.3)');
        
        // Show enhanced tooltip on mouseover
        function showTooltip(event, d) {
            let content = '';
            if (d.type === 'wallet') {
                // Determine risk level tags
                const earlyTag = d.earlyParticipant ? 
                    '<span class="tooltip-tag early-tag">Early Participant</span>' : '';
                
                let riskTag = '';
                if (d.riskLevel > 0.7) {
                    riskTag = '<span class="tooltip-tag high-risk-tag">High Risk</span>';
                } else if (d.riskLevel > 0.4) {
                    riskTag = '<span class="tooltip-tag medium-risk-tag">Medium Risk</span>';
                } else {
                    riskTag = '<span class="tooltip-tag low-risk-tag">Low Risk</span>';
                }
                
                // Add additional tags based on enhanced data
                const highActivityTag = d.highActivity ? 
                    '<span class="tooltip-tag activity-tag">High Activity</span>' : '';
                const walletTypeTag = d.walletType ? 
                    `<span class="tooltip-tag ${d.walletType}-tag">${d.walletType}</span>` : '';
                
                // Find connected tokens for this wallet
                const connectedTokensList = networkAnalyzer.networkData.links
                    .filter(link => 
                        (link.source.id === d.id && link.target.type === 'token') || 
                        (link.target.id === d.id && link.source.type === 'token')
                    )
                    .map(link => link.source.type === 'token' ? link.source : link.target);
                
                const tokenConnections = connectedTokensList.length > 0 ? 
                    `<div class="tooltip-row token-connections">
                        <span class="tooltip-label">Connected Tokens:</span>
                        <span class="tooltip-value">${connectedTokensList.length}</span>
                    </div>` : '';
                
                // Get suspicious connections count
                const suspiciousConnections = networkAnalyzer.networkData.links.filter(l => 
                    (l.source.id === d.id || l.target.id === d.id) && l.suspicious).length;
                    
                const suspiciousInfo = suspiciousConnections > 0 ? 
                    `<div class="tooltip-row suspicious-info">
                        <span class="tooltip-label">Suspicious Connections:</span>
                        <span class="tooltip-value high-risk">${suspiciousConnections}</span>
                    </div>` : '';
                
                // Add trustline position info if available
                let trustlineInfo = '';
                if (d.enhancedRiskData && d.enhancedRiskData.trustlinePosition > 0) {
                    const positionClass = d.enhancedRiskData.trustlinePosition < 10 ? 'high-risk' : 
                                       d.enhancedRiskData.trustlinePosition < 50 ? 'medium-risk' : 'low-risk';
                    
                    trustlineInfo = `
                        <div class="tooltip-row">
                            <span class="tooltip-label">Trust Line Position:</span>
                            <span class="tooltip-value ${positionClass}">${d.enhancedRiskData.trustlinePosition}</span>
                        </div>`;
                        
                    // Add early connection warning if applicable
                    if (d.enhancedRiskData.earlyConnection) {
                        trustlineInfo += `
                            <div class="tooltip-row">
                                <span class="tooltip-label">Early Participant:</span>
                                <span class="tooltip-value high-risk">Yes</span>
                            </div>`;
                    }
                    
                    // Add creator connection warning if applicable
                    if (d.enhancedRiskData.creatorConnection) {
                        trustlineInfo += `
                            <div class="tooltip-row">
                                <span class="tooltip-label">Connected to Creator:</span>
                                <span class="tooltip-value high-risk">Yes</span>
                            </div>`;
                    }
                }
                
                // Add wallet age if available
                let walletAgeInfo = '';
                if (d.enhancedRiskData && d.enhancedRiskData.walletAge > 0) {
                    walletAgeInfo = `
                        <div class="tooltip-row">
                            <span class="tooltip-label">Wallet Age:</span>
                            <span class="tooltip-value">${d.enhancedRiskData.walletAge} days</span>
                        </div>`;
                }
                
                content = `
                    <div class="tooltip-header">
                        <strong>Wallet Address</strong> ${earlyTag} ${riskTag} ${highActivityTag} ${walletTypeTag}
                    </div>
                    <div class="tooltip-address">${d.id}</div>
                    <div class="tooltip-details">
                        <div class="tooltip-row">
                            <span class="tooltip-label">Risk Level:</span>
                            <span class="tooltip-value ${getRiskClass(d.riskLevel * 100)}">${Math.round(d.riskLevel * 100)}%</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Connections:</span>
                            <span class="tooltip-value">${networkAnalyzer.networkData.links.filter(l => 
                                (l.source.id === d.id || l.target.id === d.id)).length}</span>
                        </div>
                        ${tokenConnections}
                        ${suspiciousInfo}
                        ${trustlineInfo}
                        ${walletAgeInfo}`;
                
                // Add enhanced risk data if available
                if (d.enhancedRiskData) {
                    content += `
                        <div class="tooltip-row">
                            <span class="tooltip-label">Account Age Risk:</span>
                            <span class="tooltip-value ${getRiskClass(d.enhancedRiskData.ageRisk * 100)}">${Math.round(d.enhancedRiskData.ageRisk * 100)}%</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Activity Risk:</span>
                            <span class="tooltip-value ${getRiskClass(d.enhancedRiskData.activityRisk * 100)}">${Math.round(d.enhancedRiskData.activityRisk * 100)}%</span>
                        </div>`;
                        
                    // Add transaction volume risk if available
                    if (d.enhancedRiskData.transactionVolumeRisk > 0) {
                        content += `
                            <div class="tooltip-row">
                                <span class="tooltip-label">Transaction Volume Risk:</span>
                                <span class="tooltip-value ${getRiskClass(d.enhancedRiskData.transactionVolumeRisk * 100)}">${Math.round(d.enhancedRiskData.transactionVolumeRisk * 100)}%</span>
                            </div>`;
                    }
                    
                    // Add trust line risk if available
                    if (d.enhancedRiskData.trustlineRisk > 0) {
                        content += `
                            <div class="tooltip-row">
                                <span class="tooltip-label">Trust Line Risk:</span>
                                <span class="tooltip-value ${getRiskClass(d.enhancedRiskData.trustlineRisk * 100)}">${Math.round(d.enhancedRiskData.trustlineRisk * 100)}%</span>
                            </div>`;
                    }
                }
                
                // Add early participant info if applicable
                if (d.earlyParticipant) {
                    content += `
                        <div class="tooltip-row">
                            <span class="tooltip-label">Early Participant:</span>
                            <span class="tooltip-value">Connected to token from early transactions</span>
                        </div>`;
                }
                
                // Add main node connection info if this is connected to the main node
                if (d.id !== networkAnalyzer.networkData.mainNode) {
                    const isDirectlyConnected = networkAnalyzer.networkData.links.some(l => 
                        (l.source.id === networkAnalyzer.networkData.mainNode && l.target.id === d.id) || 
                        (l.target.id === networkAnalyzer.networkData.mainNode && l.source.id === d.id));
                    
                    if (isDirectlyConnected) {
                        content += `
                            <div class="tooltip-row">
                                <span class="tooltip-label">Connection to Main:</span>
                                <span class="tooltip-value">Direct connection to main wallet</span>
                            </div>`;
                    }
                }
                
                content += `
                    </div>
                    <div class="tooltip-footer">Click for more details</div>
                `;
            } else if (d.type === 'token') {
                content = `
                    <div class="tooltip-header">
                        <strong>Token</strong>
                        ${d.riskLevel > 0.7 ? '<span class="tooltip-tag suspicious-tag">High Risk</span>' : ''}
                    </div>
                    <div class="tooltip-address">${d.name}</div>
                    <div class="tooltip-details">
                        <div class="tooltip-row">
                            <span class="tooltip-label">Issuer:</span>
                            <span class="tooltip-value">${formatAddress(d.issuer)}</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Risk Level:</span>
                            <span class="tooltip-value ${getRiskClass(d.riskLevel * 100)}">${Math.round(d.riskLevel * 100)}%</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Issue Date:</span>
                            <span class="tooltip-value">${d.issueDate}</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Holders:</span>
                            <span class="tooltip-value">${d.holders || 'Unknown'}</span>
                        </div>
                    </div>
                    <div class="tooltip-footer">Click for more details</div>
                `;
            }
            
            tooltip.html(content)
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 28) + 'px')
                .transition()
                .duration(200)
                .style('opacity', 1);
        }
        
        // Hide tooltip on mouseout
        function hideTooltip() {
            tooltip.transition()
                .duration(500)
                .style('opacity', 0);
        }
        
        // Function for node click to show detailed information
        function nodeClicked(event, d) {
            // Stop event propagation
            event.stopPropagation();
            console.log('Node clicked:', d);
            
            if (d.type === 'wallet') {
                showWalletDetails(d.id);
            } else if (d.type === 'token') {
                showTokenDetails(d, networkAnalyzer.networkData);
            }
            
            // Scroll to the scan results section
            setTimeout(() => {
                const resultsPanel = document.querySelector('.results-panel');
                if (resultsPanel) {
                    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }, 100);
        }
        
        // Function to show wallet details in the scan results area
        function showWalletDetails(walletId) {
            // Show loading state
            scanResults.innerHTML = '<p class="loading">Loading wallet details...</p>';
            
            // Get wallet details
            Promise.all([
                xrplService.getAccountInfo(walletId),
                xrplService.getAccountTransactions(walletId, 10),
                xrplService.getAccountBalances(walletId),
                networkAnalyzer.analyzeWalletHistory(walletId)
            ])
            .then(([accountInfo, transactions, balances, walletHistory]) => {
                let detailsHTML = `
                    <div class="wallet-details">
                        <div class="details-header">
                            <h4>Wallet Details</h4>
                            <div class="wallet-address">${walletId}</div>
                        </div>
                        
                        <div class="details-section">
                            <h5>Account Information</h5>
                            <div class="details-grid">
                                <div class="detail-item">
                                    <span class="detail-label">XRP Balance:</span>
                                    <span class="detail-value">${balances.xrp || 'N/A'} XRP</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Sequence:</span>
                                    <span class="detail-value">${accountInfo.Sequence || 'N/A'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Owner Count:</span>
                                    <span class="detail-value">${accountInfo.OwnerCount || 0}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Unique Counterparties:</span>
                                    <span class="detail-value">${walletHistory.uniqueCounterparties.length}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="details-section">
                            <h5>Transaction Analysis</h5>
                            <div class="transaction-analysis">
                                <div class="analysis-summary">
                                    <div class="summary-item">
                                        <span class="summary-label">Total Analyzed:</span>
                                        <span class="summary-value">${walletHistory.earlyTxs.length + walletHistory.recentTxs.length}</span>
                                    </div>
                                    <div class="summary-item">
                                        <span class="summary-label">Payments:</span>
                                        <span class="summary-value">${walletHistory.patternAnalysis.paymentFrequency}</span>
                                    </div>
                                    <div class="summary-item">
                                        <span class="summary-label">Trustlines:</span>
                                        <span class="summary-value">${walletHistory.patternAnalysis.trustlines}</span>
                                    </div>
                                    <div class="summary-item">
                                        <span class="summary-label">Token Issuances:</span>
                                        <span class="summary-value">${walletHistory.patternAnalysis.tokenIssuances}</span>
                                    </div>
                                </div>
                                
                                ${renderTokenInteractions(walletHistory.tokenInteractions)}
                                
                                ${renderUnusualPatterns(walletHistory.patternAnalysis.unusualPatterns)}
                            </div>
                        </div>
                        
                        <div class="details-section">
                            <h5>Token Holdings</h5>
                            ${renderTokenHoldings(balances.tokens)}
                        </div>
                        
                        <div class="details-section">
                            <h5>Early Transactions <small>(First ${walletHistory.earlyTxs.length})</small></h5>
                            ${renderTransactionTable(walletHistory.earlyTxs.slice(0, 5), true)}
                            ${walletHistory.earlyTxs.length > 5 ? '<button class="btn btn-small view-all-early">View All Early</button>' : ''}
                        </div>
                        
                        <div class="details-section">
                            <h5>Recent Transactions <small>(Latest ${walletHistory.recentTxs.length})</small></h5>
                            ${renderTransactionTable(walletHistory.recentTxs.slice(0, 5))}
                            ${walletHistory.recentTxs.length > 5 ? '<button class="btn btn-small view-all-recent">View All Recent</button>' : ''}
                        </div>
                        
                        <div class="details-actions">
                            <button class="btn" id="view-all-txs">View All Transactions</button>
                            <button class="btn" id="check-wallet-trustlines">View Trustlines</button>
                            <button class="btn" id="back-to-network">Back to Network</button>
                        </div>
                    </div>
                `;
                
                scanResults.innerHTML = detailsHTML;
                
                // Add event listeners to the buttons
                document.getElementById('view-all-txs').addEventListener('click', () => {
                    viewTransactionHistory(walletId);
                });
                
                document.getElementById('check-wallet-trustlines').addEventListener('click', () => {
                    checkTrustlines(walletId);
                });
                
                document.getElementById('back-to-network').addEventListener('click', () => {
                    // Redisplay the previous scan results
                    displayResults(networkAnalyzer.networkData, networkAnalyzer.getFindings());
                });
                
                // Add event listeners for early/recent transaction buttons if they exist
                const viewAllEarlyBtn = document.querySelector('.view-all-early');
                if (viewAllEarlyBtn) {
                    viewAllEarlyBtn.addEventListener('click', () => {
                        const earlyTxsSection = document.querySelector('.details-section:nth-of-type(4)');
                        earlyTxsSection.innerHTML = `
                            <h5>Early Transactions <small>(First ${walletHistory.earlyTxs.length})</small></h5>
                            ${renderTransactionTable(walletHistory.earlyTxs, true)}
                        `;
                    });
                }
                
                const viewAllRecentBtn = document.querySelector('.view-all-recent');
                if (viewAllRecentBtn) {
                    viewAllRecentBtn.addEventListener('click', () => {
                        const recentTxsSection = document.querySelector('.details-section:nth-of-type(5)');
                        recentTxsSection.innerHTML = `
                            <h5>Recent Transactions <small>(Latest ${walletHistory.recentTxs.length})</small></h5>
                            ${renderTransactionTable(walletHistory.recentTxs)}
                        `;
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching wallet details:', error);
                scanResults.innerHTML = `<p class="error">Error loading wallet details: ${error.message}</p>`;
            });
        }
        
        // Function to show token details in the scan results area
        function showTokenDetails(token, networkData) {
            // Show loading state
            scanResults.innerHTML = '<p class="loading">Loading token details...</p>';
            
            // Get token holders from the network data
            const holders = networkData.links
                .filter(link => 
                    (link.source.id === token.id && link.target.type === 'wallet') || 
                    (link.target.id === token.id && link.source.type === 'wallet')
                )
                .map(link => link.source.type === 'wallet' ? link.source : link.target);
            
            // Get early participants for this token
            const earlyParticipants = holders.filter(holder => holder.earlyParticipant);
            
            // Fetch additional token information if possible
            Promise.all([
                // Try to get token metadata if available
                token.issuer ? xrplService.getIssuedTokens(token.issuer) : Promise.resolve([])
            ]).then(([issuedTokens]) => {
                // Find this specific token in the issued tokens list
                const tokenDetails = issuedTokens.find(t => t.currency === token.name) || token;
                
                let detailsHTML = `
                    <div class="token-details">
                        <div class="details-header">
                            <h4>Token Details</h4>
                            <div class="token-name">${convertHexToString(token.name)}</div>
                        </div>
                        
                        <div class="details-section">
                            <h5>Token Information</h5>
                            <div class="details-grid">
                                <div class="detail-item">
                                    <span class="detail-label">Issuer:</span>
                                    <span class="detail-value detail-link" data-address="${token.issuer}">${token.issuer}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Currency Code:</span>
                                    <span class="detail-value">${token.name}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Issue Date:</span>
                                    <span class="detail-value">${token.issueDate || 'Unknown'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Risk Level:</span>
                                    <span class="detail-value ${getRiskClass(token.riskLevel * 100)}">${Math.round(token.riskLevel * 100)}%</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="details-section">
                            <h5>Early Participants (${earlyParticipants.length})</h5>
                            ${renderHoldersList(earlyParticipants, true)}
                        </div>
                        
                        <div class="details-section">
                            <h5>All Holders (${holders.length})</h5>
                            ${renderHoldersList(holders, false)}
                        </div>
                        
                        <div class="details-actions">
                            <button class="btn" id="back-to-network">Back to Network</button>
                        </div>
                    </div>
                `;
                
                scanResults.innerHTML = detailsHTML;
                
                // Add event listeners
                document.getElementById('back-to-network').addEventListener('click', () => {
                    // Redisplay the previous scan results
                    displayResults(networkAnalyzer.networkData, networkAnalyzer.getFindings());
                });
                
                // Add event listeners to address links
                document.querySelectorAll('.detail-link').forEach(link => {
                    link.addEventListener('click', (e) => {
                        const address = e.target.getAttribute('data-address');
                        if (address) {
                            showWalletDetails(address);
                        }
                    });
                });
            }).catch(error => {
                console.error('Error fetching token details:', error);
                scanResults.innerHTML = `<p class="error">Error loading token details: ${error.message}</p>`;
            });
        }
        
        // Render token holdings list
        function renderTokenHoldings(tokens) {
            if (!tokens || tokens.length === 0) {
                return '<div class="empty-list">No tokens found</div>';
            }
            
            let html = `
                <table class="details-table">
                    <thead>
                        <tr>
                            <th>Currency</th>
                            <th>Issuer</th>
                            <th>Balance</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            tokens.forEach(token => {
                html += `
                    <tr>
                        <td>${convertHexToString(token.currency)}</td>
                        <td class="address detail-link" data-address="${token.issuer}">${formatAddress(token.issuer)}</td>
                        <td>${token.value || '0'}</td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            return html;
        }
        
        // Render transaction table
        function renderTransactionTable(transactions, isEarly) {
            if (!transactions || transactions.length === 0) {
                return '<div class="empty-list">No transactions found</div>';
            }
            
            let html = `
                <table class="details-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Destination</th>
                            <th>Amount</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            transactions.forEach(tx => {
                const amount = formatAmount(tx.Amount);
                // Determine if this is a token transaction
                const isTokenTx = typeof tx.Amount === 'object' && tx.Amount.currency;
                
                html += `
                    <tr class="${isTokenTx ? 'token-tx' : ''}">
                        <td>${tx.TransactionType || 'Unknown'}</td>
                        <td class="address detail-link" data-address="${tx.Destination || ''}">${
                            tx.Destination ? formatAddress(tx.Destination) : 'N/A'
                        }</td>
                        <td>${isTokenTx ? `${amount} <span class="token-name">${convertHexToString(tx.Amount.currency)}</span>` : amount}</td>
                        <td>${formatDate(tx.date)}</td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            return html;
        }
        
        // Render holders list
        function renderHoldersList(holders, isEarlyParticipants) {
            if (!holders || holders.length === 0) {
                return `<div class="empty-list">No ${isEarlyParticipants ? 'early participants' : 'holders'} found</div>`;
            }
            
            let html = `
                <table class="details-table">
                    <thead>
                        <tr>
                            <th>Wallet Address</th>
                            <th>Risk Level</th>
                            ${isEarlyParticipants ? '<th>Transaction Info</th>' : ''}
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            holders.forEach(holder => {
                html += `
                    <tr>
                        <td class="address detail-link" data-address="${holder.id}">${formatAddress(holder.id)}</td>
                        <td class="${getRiskClass(holder.riskLevel * 100)}">${Math.round(holder.riskLevel * 100)}%</td>
                        ${isEarlyParticipants ? `<td>${holder.earlyTxInfo || 'Early participant'}</td>` : ''}
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            return html;
        }

        /**
         * Render token interactions for display
         * @param {Object} tokenInteractions - Token interaction data
         * @returns {string} - HTML for token interactions
         */
        function renderTokenInteractions(tokenInteractions) {
            if (Object.keys(tokenInteractions).length === 0) {
                return '<p class="empty-list">No token interactions found</p>';
            }
            
            let html = `
                <div class="token-interactions">
                    <h6>Token Activity</h6>
                    <table class="details-table">
                        <thead>
                            <tr>
                                <th>Token</th>
                                <th>Sent</th>
                                <th>Received</th>
                                <th>Volume</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            for (const [currency, data] of Object.entries(tokenInteractions)) {
                html += `
                    <tr>
                        <td>${convertHexToString(currency)}</td>
                        <td>${data.sent}</td>
                        <td>${data.received}</td>
                        <td>${formatNumberWithCommas(data.volume.toFixed(2))}</td>
                    </tr>
                `;
            }
            
            html += `
                        </tbody>
                    </table>
                </div>
            `;
            
            return html;
        }

        /**
         * Render unusual patterns for display
         * @param {Array} patterns - Unusual patterns
         * @returns {string} - HTML for unusual patterns
         */
        function renderUnusualPatterns(patterns) {
            if (!patterns || patterns.length === 0) {
                return '';
            }
            
            let html = `
                <div class="unusual-patterns">
                    <h6>Unusual Activity Detected</h6>
                    <ul class="patterns-list">
            `;
            
            for (const pattern of patterns) {
                html += `
                    <li class="pattern-item ${pattern.severity}">
                        <span class="pattern-icon">${getSeverityIcon(pattern.severity)}</span>
                        <span class="pattern-description">${pattern.description}</span>
                    </li>
                `;
            }
            
            html += `
                    </ul>
                </div>
            `;
            
            return html;
        }
    }
}

// Function to initialize the app with mock data if XRPL service can't be loaded
function initializeAppWithMockData() {
    // DOM elements
    const walletInput = document.getElementById('wallet-address');
    const scanButton = document.getElementById('scan-button');
    const networkViz = document.getElementById('network-visualization');
    const scanResults = document.getElementById('scan-results');
    const riskScore = document.getElementById('risk-score');
    const connectedWallets = document.getElementById('connected-wallets');
    const connectedTokens = document.getElementById('connected-tokens');

    // Add forest pattern to the analyzer section
    const analyzerSection = document.getElementById('analyzer');
    const forestPattern = document.createElement('div');
    forestPattern.className = 'forest-pattern';
    if (analyzerSection && !document.querySelector('.forest-pattern')) {
        analyzerSection.appendChild(forestPattern);
    }

    // XRPL Network visualization setup
    let viz = null;
    let simulation = null;
    
    // Initialize the visualization with placeholder data
    initVisualization();
    
    // Event listeners
    scanButton.addEventListener('click', performScan);
    
    // Original functions remain unchanged
    // ... (continue with the original implementation)
}

// Helper function to format an address for display
function formatAddress(address) {
    if (!address) return 'Unknown';
    return address.substring(0, 6) + '...' + address.substring(address.length - 4);
}

// Helper function to get risk class
function getRiskClass(score) {
    if (score > 70) return 'high-risk';
    if (score > 30) return 'medium-risk';
    return 'low-risk';
}

// Function to format numbers with commas for readability
function formatNumberWithCommas(number) {
    if (!number) return '0';
    
    // Convert to number if it's a string
    const num = typeof number === 'string' ? parseFloat(number) : number;
    
    // Format with commas and limit to 2 decimal places
    return num.toLocaleString('en-US', {
        maximumFractionDigits: 2,
        minimumFractionDigits: 0
    });
} 

// Initialize event listeners for feature buttons
document.getElementById('alerts-button').addEventListener('click', function() {
    showComingSoonAlert('Alert System');
});

document.getElementById('track-wallet-button').addEventListener('click', function() {
    showComingSoonAlert('Wallet Tracking');
});

/**
 * Show "Coming Soon" alert for features under development
 * @param {string} featureName - Name of the coming feature
 */
function showComingSoonAlert(featureName) {
    const alertBox = document.createElement('div');
    alertBox.className = 'coming-soon-alert';
    alertBox.innerHTML = `
        <div class="alert-content">
            <h4>${featureName} - Coming Soon!</h4>
            <p>This feature is currently under development and will be available in a future update.</p>
            <p class="alert-eta">Expected in Q2 2024</p>
            <button class="alert-close-btn">Got it</button>
        </div>
    `;
    
    document.body.appendChild(alertBox);
    
    // Add fade-in effect
    setTimeout(() => {
        alertBox.classList.add('show');
    }, 10);
    
    // Handle close button
    alertBox.querySelector('.alert-close-btn').addEventListener('click', function() {
        alertBox.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(alertBox);
        }, 300);
    });
    
    // Auto-close after 5 seconds
    setTimeout(() => {
        if (document.body.contains(alertBox)) {
            alertBox.classList.remove('show');
            setTimeout(() => {
                if (document.body.contains(alertBox)) {
                    document.body.removeChild(alertBox);
                }
            }, 300);
        }
    }, 5000);
}