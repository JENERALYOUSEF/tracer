// Cyber Detective Tools Functionality

// IP Address Investigator
function investigateIP() {
    const ipInput = document.querySelector('#ipAddress');
    const resultsArea = document.querySelector('#ipResults');
    
    if (ipInput && ipInput.value) {
        resultsArea.style.display = 'block';
        // In a real implementation, this would make an API call to an IP geolocation service
        // For demo purposes, we'll show mock data
        document.querySelector('.location-data').textContent = 'New York, USA';
        document.querySelector('.isp-data').textContent = 'Example ISP';
        document.querySelector('.type-data').textContent = 'Residential';
    }
}

// Domain Inspector
function inspectDomain() {
    const domainInput = document.querySelector('#domainName');
    const resultsArea = document.querySelector('#domainResults');
    
    if (domainInput && domainInput.value) {
        resultsArea.style.display = 'block';
        // Mock data for demonstration
        document.querySelector('.reg-date').textContent = '2024-01-01';
        document.querySelector('.ssl-status').textContent = 'Valid (SHA-256)';
        document.querySelector('.host-location').textContent = 'United States';
    }
}

// Port Detective
function investigatePort() {
    const portInput = document.querySelector('#portNumber');
    const resultsArea = document.querySelector('#portResults');
    
    if (portInput && portInput.value) {
        resultsArea.style.display = 'block';
        const portNumber = parseInt(portInput.value);
        
        // Mock data based on common ports
        let service = '--';
        let protocol = '--';
        let notes = '--';
        
        switch(portNumber) {
            case 80:
                service = 'HTTP (Web)';
                protocol = 'TCP';
                notes = 'Standard web traffic port, should be secured';
                break;
            case 443:
                service = 'HTTPS (Secure Web)';
                protocol = 'TCP';
                notes = 'Secure web traffic port, recommended for web services';
                break;
            case 21:
                service = 'FTP';
                protocol = 'TCP';
                notes = 'File transfer port, consider using SFTP instead';
                break;
            case 22:
                service = 'SSH';
                protocol = 'TCP';
                notes = 'Secure shell access, keep updated and monitored';
                break;
            case 25:
                service = 'SMTP';
                protocol = 'TCP';
                notes = 'Email transmission, requires proper security';
                break;
            case 53:
                service = 'DNS';
                protocol = 'TCP/UDP';
                notes = 'Domain name resolution, critical for security';
                break;
            default:
                service = 'Unknown';
                protocol = '--';
                notes = 'Port not in common list';
        }
        
        document.querySelector('.service-name').textContent = service;
        document.querySelector('.protocol-type').textContent = protocol;
        document.querySelector('.security-notes').textContent = notes;
    }
}

// Digital Footprint Analyzer
function analyzeFootprint() {
    const usernameInput = document.querySelector('#usernameInput');
    const resultsArea = document.querySelector('#footprintResults');
    
    if (usernameInput && usernameInput.value) {
        resultsArea.style.display = 'block';
        
        // Mock analysis data
        const mockAnalysis = {
            webPresence: 'Medium',
            privacyScore: '65/100',
            recommendations: 'Enable 2FA, review privacy settings'
        };
        
        document.querySelector('.web-presence').textContent = mockAnalysis.webPresence;
        document.querySelector('.privacy-score').textContent = mockAnalysis.privacyScore;
        document.querySelector('.recommendations').textContent = mockAnalysis.recommendations;
    }
}

// Initialize event listeners when the document is loaded
document.addEventListener('DOMContentLoaded', () => {
    // IP Address Investigator
    const investigateBtn = document.querySelector('#investigateIP');
    if (investigateBtn) {
        investigateBtn.addEventListener('click', investigateIP);
    }
    
    // Domain Inspector
    const inspectBtn = document.querySelector('#inspectDomain');
    if (inspectBtn) {
        inspectBtn.addEventListener('click', inspectDomain);
    }
    
    // Port Detective
    const portBtn = document.querySelector('#investigatePort');
    if (portBtn) {
        portBtn.addEventListener('click', investigatePort);
    }
    
    // Digital Footprint Analyzer
    const footprintBtn = document.querySelector('#analyzeFootprint');
    if (footprintBtn) {
        footprintBtn.addEventListener('click', analyzeFootprint);
    }
});
