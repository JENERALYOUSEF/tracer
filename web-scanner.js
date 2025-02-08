// Advanced Web Vulnerability Scanner
document.addEventListener('DOMContentLoaded', function() {
    console.log('Web Scanner Script Loaded');

    // Get all required elements
    const startScan = document.getElementById('startScan');
    const scannerUrl = document.getElementById('scannerUrl');
    const scanProgress = document.getElementById('scanProgress');
    const scanResults = document.getElementById('scanResults');
    const vulnerabilityList = document.getElementById('vulnerabilityList');

    // Validate element existence
    if (!startScan) console.error('Start Scan button not found');
    if (!scannerUrl) console.error('Scanner URL input not found');
    if (!scanProgress) console.error('Scan Progress element not found');
    if (!scanResults) console.error('Scan Results element not found');
    if (!vulnerabilityList) console.error('Vulnerability List element not found');

    // Vulnerability scanning functions
    function checkXSS(html) {
        const xssPatterns = [
            /<script>/i,
            /javascript:/i,
            /onerror=/i,
            /onload=/i
        ];

        const vulnerabilities = xssPatterns.filter(pattern => pattern.test(html));
        return vulnerabilities.length > 0 ? {
            type: 'Cross-Site Scripting (XSS)',
            severity: 'high',
            description: 'Potential XSS vulnerability detected through script tags or event handlers',
            recommendation: 'Implement input sanitization and output encoding'
        } : null;
    }

    function checkSQLi(url) {
        const sqlInjectionPatterns = [
            /\b(SELECT|UNION|INSERT|DELETE|DROP)\b/i,
            /'\s*OR\s*'1'='1/i,
            /;\s*--/
        ];

        return sqlInjectionPatterns.some(pattern => pattern.test(url)) ? {
            type: 'SQL Injection',
            severity: 'high',
            description: 'Potential SQL injection vulnerability detected in URL',
            recommendation: 'Use parameterized queries and validate input'
        } : null;
    }

    function checkFileUpload(url) {
        const dangerousExtensions = [
            /\.php/i,
            /\.aspx/i,
            /\.jsp/i,
            /\.exe/i
        ];

        return dangerousExtensions.some(pattern => pattern.test(url)) ? {
            type: 'Insecure File Upload',
            severity: 'medium',
            description: 'Potential dangerous file upload extension detected',
            recommendation: 'Restrict file upload to safe extensions'
        } : null;
    }

    function checkRCE(url) {
        const rcePatterns = [
            /\$\(/,  // Command substitution
            /;/,     // Command chaining
            /\|\|/   // Conditional execution
        ];

        return rcePatterns.some(pattern => pattern.test(url)) ? {
            type: 'Remote Code Execution',
            severity: 'critical',
            description: 'Potential remote code execution vulnerability detected',
            recommendation: 'Sanitize and validate all user inputs'
        } : null;
    }

    // Ensure the event listener is added
    if (startScan) {
        startScan.addEventListener('click', async function(event) {
            console.log('Scan button clicked');
            event.preventDefault(); // Prevent default form submission

            const url = scannerUrl.value.trim();
            console.log('Scanned URL:', url);
            
            if (!url) {
                alert('Please enter a valid URL');
                return;
            }

            // Reset UI
            scanProgress.style.display = 'block';
            scanResults.style.display = 'none';
            vulnerabilityList.innerHTML = '';
            startScan.disabled = true;

            const updateProgress = (percent) => {
                console.log(`Progress: ${percent}%`);
                scanProgress.querySelector('.progress-bar').style.width = `${percent}%`;
            };

            try {
                updateProgress(20);

                // Fetch the webpage content
                console.log('Fetching URL content');
                const response = await fetch(url, {
                    mode: 'no-cors' // Add CORS bypass
                });
                
                console.log('Fetch response:', response);
                const html = await response.text();
                console.log('HTML content length:', html.length);

                updateProgress(50);

                // Perform vulnerability checks
                const vulnerabilities = [
                    checkXSS(html),
                    checkSQLi(url),
                    checkFileUpload(url),
                    checkRCE(url)
                ].filter(vuln => vuln !== null);

                console.log('Detected vulnerabilities:', vulnerabilities);

                updateProgress(80);

                // Display results
                if (vulnerabilities.length > 0) {
                    vulnerabilities.forEach(vuln => {
                        const vulnerabilityItem = document.createElement('div');
                        vulnerabilityItem.className = `alert ${vuln.severity === 'critical' ? 'alert-danger' : 'alert-warning'}`;
                        vulnerabilityItem.innerHTML = `
                            <h5 class="alert-heading">
                                <i class="fas fa-bug"></i> ${vuln.type}
                                <span class="badge bg-${vuln.severity === 'critical' ? 'danger' : 'warning'} float-end">${vuln.severity.toUpperCase()} Risk</span>
                            </h5>
                            <p><strong>Description:</strong> ${vuln.description}</p>
                            <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                        `;
                        vulnerabilityList.appendChild(vulnerabilityItem);
                    });
                } else {
                    const noVulnerabilities = document.createElement('div');
                    noVulnerabilities.className = 'alert alert-success';
                    noVulnerabilities.innerHTML = `
                        <h5>No Vulnerabilities Detected!</h5>
                        <p>Your website appears to be secure against the tested vulnerability types.</p>
                    `;
                    vulnerabilityList.appendChild(noVulnerabilities);
                }

                updateProgress(100);
                scanResults.style.display = 'block';

            } catch (error) {
                console.error('Scan error:', error);
                const errorMessage = document.createElement('div');
                errorMessage.className = 'alert alert-danger';
                errorMessage.textContent = `Scan failed: ${error.message}. Please check the URL and try again.`;
                vulnerabilityList.appendChild(errorMessage);
            } finally {
                startScan.disabled = false;
            }
        });
    } else {
        console.error('Start Scan button event listener could not be added');
    }
});