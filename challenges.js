// CTF Challenges Data
const challenges = {
    web: {
        easy: [
            {
                id: 'web_e1',
                title: 'Inspector Gadget',
                difficulty: 'easy',
                points: 100,
                description: "Something's hidden in the page source. Can you find it?",
                objective: "Find the flag in the HTML source code.",
                flag: 'flag{source_master}',
                hints: ['Right-click and View Page Source', 'Look for HTML comments'],
                solution: ['View the page source', 'Find the HTML comment <!-- flag{source_master} -->']
            },
            {
                id: 'web_e2',
                title: 'Cookie Monster',
                difficulty: 'easy',
                points: 100,
                description: "There's a secret cookie on this page.",
                objective: "Find and decode the cookie value.",
                flag: 'flag{cookie_hunter}',
                hints: ['Check browser developer tools', 'Look in the Storage/Cookies tab'],
                solution: ['Open DevTools', 'Go to Storage/Cookies', 'Find and decode the cookie']
            },
            {
                id: 'web_e3',
                title: 'Robot Rules',
                difficulty: 'easy',
                points: 100,
                description: "The robots.txt file is hiding something.",
                objective: "Find the secret in robots.txt",
                flag: 'flag{robots_rule}',
                hints: ['Visit /robots.txt', 'Look for Disallow entries'],
                solution: ['Navigate to /robots.txt', 'Find hidden directory', 'Access the secret page']
            },
            {
                id: 'web_e4',
                title: 'Web Injection 101',
                difficulty: 'easy',
                points: 100,
                description: 'Learn basic SQL injection techniques',
                objective: 'Learn SQL injection',
                flag: 'flag{sql_injection_master}',
                hints: ['Try using single quotes', 'What happens when you add OR 1=1?'],
                solution: ['Try SQL injection', 'Learn from it']
            },
            {
                id: 'web_e5',
                title: 'Cookie Monster',
                difficulty: 'easy',
                points: 150,
                description: 'Manipulate cookies to gain access',
                objective: 'Manipulate cookies',
                flag: 'flag{cookie_manipulation_pro}',
                hints: ['Check your browser\'s cookie storage', 'Try modifying the admin cookie'],
                solution: ['Modify cookies', 'Gain access']
            }
        ],
        medium: [
            {
                id: 'web_m1',
                title: 'SQL Injection 101',
                difficulty: 'medium',
                points: 200,
                description: "Login to the admin account without knowing the password.",
                objective: "Exploit basic SQL injection vulnerability.",
                flag: 'flag{sql_master}',
                hints: ['Try using single quotes in the input', "What happens if you add OR '1'='1'?"],
                solution: ["Enter admin' OR '1'='1", 'The query becomes true for all rows', 'Access granted']
            },
            {
                id: 'web_m2',
                title: 'XSS Training',
                difficulty: 'medium',
                points: 200,
                description: "Execute JavaScript in the comment section.",
                objective: "Demonstrate basic XSS vulnerability.",
                flag: 'flag{xss_alert}',
                hints: ['Try adding HTML tags', 'What about script tags?'],
                solution: ['Insert <script>alert("XSS")</script>', 'JavaScript executes']
            },
            {
                id: 'web_m3',
                title: 'CSRF Attack',
                difficulty: 'medium',
                points: 200,
                description: "Create a form that automatically submits to change the admin's password.",
                objective: "Exploit CSRF vulnerability.",
                flag: 'flag{csrf_master}',
                hints: ['Check if CSRF tokens are used', 'Create an auto-submitting form'],
                solution: ['Create malicious form', 'Auto-submit with JavaScript', 'Password changed']
            },
            {
                id: 'web_m4',
                title: 'XSS Adventure',
                difficulty: 'medium',
                points: 200,
                description: 'Execute cross-site scripting attacks',
                objective: 'Execute XSS',
                flag: 'flag{xss_warrior}',
                hints: ['Look for input fields that reflect your input', 'Try bypassing basic filters'],
                solution: ['Find XSS vulnerability', 'Execute XSS']
            }
        ],
        hard: [
            {
                id: 'web_h1',
                title: 'JWT Breaker',
                difficulty: 'hard',
                points: 300,
                description: "The JWT token is weak. Can you forge an admin token?",
                objective: "Exploit JWT vulnerability to gain admin access.",
                flag: 'flag{jwt_cracked}',
                hints: ['Check the JWT algorithm', 'What if algorithm is "none"?'],
                solution: ['Decode JWT', 'Change algorithm to none', 'Remove signature', 'Create admin token']
            },
            {
                id: 'web_h2',
                title: 'SSRF Safari',
                difficulty: 'hard',
                points: 300,
                description: "The image loader accepts URLs. Can you access internal services?",
                objective: "Exploit SSRF vulnerability to access localhost.",
                flag: 'flag{ssrf_master}',
                hints: ['Try accessing localhost', 'What internal ports are open?'],
                solution: ['Try localhost URLs', 'Scan internal ports', 'Access internal service']
            },
            {
                id: 'web_h3',
                title: 'RCE Master',
                difficulty: 'hard',
                points: 300,
                description: "The file upload feature is vulnerable. Can you get remote code execution?",
                objective: "Achieve RCE through file upload.",
                flag: 'flag{rce_achieved}',
                hints: ['Check file extension validation', 'Try PHP files'],
                solution: ['Upload PHP shell', 'Bypass validation', 'Execute commands']
            },
            {
                id: 'web_h4',
                title: 'RCE Master',
                difficulty: 'hard',
                points: 300,
                description: 'Achieve remote code execution',
                objective: 'Achieve RCE',
                flag: 'flag{rce_expert_level}',
                hints: ['Check for command injection vulnerabilities', 'Look at the file upload function'],
                solution: ['Find RCE vulnerability', 'Achieve RCE']
            }
        ]
    },
    forensics: {
        easy: [
            {
                id: 'forensics_e1',
                title: 'Hidden Text',
                difficulty: 'easy',
                points: 100,
                description: "This text file has more than meets the eye.",
                objective: "Find hidden text using basic tools.",
                flag: 'flag{strings_found}',
                hints: ['Try the strings command', 'Look for unusual patterns'],
                solution: ['Use strings command', 'Find hidden flag in output']
            },
            {
                id: 'forensics_e2',
                title: 'Metadata Explorer',
                difficulty: 'easy',
                points: 100,
                description: "Check the image metadata for clues.",
                objective: "Find information in EXIF data.",
                flag: 'flag{exif_master}',
                hints: ['Use exiftool', 'Check all metadata fields'],
                solution: ['Run exiftool', 'Find flag in comments']
            },
            {
                id: 'forensics_e3',
                title: 'File Signature',
                difficulty: 'easy',
                points: 100,
                description: "This file has the wrong extension.",
                objective: "Identify true file type.",
                flag: 'flag{magic_bytes}',
                hints: ['Check file signature', 'Use file command'],
                solution: ['Check magic bytes', 'Identify true type']
            },
            {
                id: 'for_e1',
                title: 'Hidden in Plain Sight',
                difficulty: 'easy',
                points: 100,
                description: 'Find hidden data in images',
                objective: 'Find hidden data',
                flag: 'flag{steganography_101}',
                hints: ['Try using steghide', 'Check the metadata'],
                solution: ['Use steghide', 'Find hidden data']
            }
        ],
        medium: [
            {
                id: 'forensics_m1',
                title: 'Memory Dump',
                difficulty: 'medium',
                points: 200,
                description: "Analyze this memory dump to find user activity.",
                objective: "Use memory forensics tools to find evidence.",
                flag: 'flag{volatility_master}',
                hints: ['Try Volatility', 'Look for running processes'],
                solution: ['Use Volatility', 'Analyze processes', 'Find suspicious activity']
            },
            {
                id: 'forensics_m2',
                title: 'Network Capture',
                difficulty: 'medium',
                points: 200,
                description: "Find suspicious traffic in this PCAP file.",
                objective: "Analyze network traffic for malicious activity.",
                flag: 'flag{wireshark_pro}',
                hints: ['Use Wireshark', 'Look for unusual protocols'],
                solution: ['Open in Wireshark', 'Filter traffic', 'Find malicious packets']
            },
            {
                id: 'forensics_m3',
                title: 'Registry Analysis',
                difficulty: 'medium',
                points: 200,
                description: "Find evidence of persistence in the registry.",
                objective: "Identify malware persistence mechanisms.",
                flag: 'flag{reg_hunter}',
                hints: ['Check common persistence locations', 'Look for unusual entries'],
                solution: ['Analyze registry', 'Find malicious keys', 'Document persistence']
            },
            {
                id: 'for_m1',
                title: 'Memory Analysis',
                difficulty: 'medium',
                points: 200,
                description: 'Analyze memory dumps',
                objective: 'Analyze memory',
                flag: 'flag{memory_master}',
                hints: ['Use Volatility', 'Look for running processes'],
                solution: ['Use Volatility', 'Analyze memory']
            }
        ],
        hard: [
            {
                id: 'forensics_h1',
                title: 'Disk Recovery',
                difficulty: 'hard',
                points: 300,
                description: "Recover deleted files from this disk image.",
                objective: "Use advanced forensics tools for file recovery.",
                flag: 'flag{recovery_expert}',
                hints: ['Try file carving tools', 'Look for file signatures'],
                solution: ['Use file carving', 'Recover deleted files', 'Find flag in recovered data']
            },
            {
                id: 'forensics_h2',
                title: 'Malware Analysis',
                difficulty: 'hard',
                points: 300,
                description: "Analyze this malware sample in a safe environment.",
                objective: "Perform static and dynamic analysis.",
                flag: 'flag{malware_hunter}',
                hints: ['Use a VM', 'Try reverse engineering tools'],
                solution: ['Setup analysis environment', 'Perform analysis', 'Document behavior']
            },
            {
                id: 'forensics_h3',
                title: 'APT Investigation',
                difficulty: 'hard',
                points: 300,
                description: "Track the activities of an APT group.",
                objective: "Analyze multiple data sources to track APT.",
                flag: 'flag{apt_tracker}',
                hints: ['Correlate multiple sources', 'Look for patterns'],
                solution: ['Analyze logs', 'Track lateral movement', 'Document timeline']
            },
            {
                id: 'for_h1',
                title: 'Network Forensics',
                difficulty: 'hard',
                points: 300,
                description: 'Analyze network traffic',
                objective: 'Analyze network traffic',
                flag: 'flag{packet_analyzer}',
                hints: ['Check the PCAP file', 'Look for suspicious HTTP requests'],
                solution: ['Analyze network traffic', 'Find suspicious activity']
            }
        ]
    },
    // Add similar structure for osint, crypto, steganography, and linux categories
    // Each with easy, medium, and hard sections containing 3 challenges each
};

function loadChallenges() {
    const categories = ['web', 'forensics', 'osint', 'crypto', 'steganography', 'linux'];
    const difficulties = ['easy', 'medium', 'hard'];
    
    categories.forEach(category => {
        difficulties.forEach(difficulty => {
            const container = document.querySelector(`#${category}-${difficulty}`);
            if (container && challenges[category] && challenges[category][difficulty]) {
                challenges[category][difficulty].forEach(challenge => {
                    const card = createChallengeCard(challenge);
                    container.appendChild(card);
                });
            }
        });
    });
}

function createChallengeCard(challenge) {
    const card = document.createElement('div');
    card.className = 'col-md-4';
    card.innerHTML = `
        <div class="challenge-card">
            <span class="difficulty ${challenge.difficulty}">${challenge.difficulty}</span>
            <span class="points-badge"><i class="fas fa-star"></i>${challenge.points}</span>
            <h3>${challenge.title}</h3>
            <p>${challenge.description}</p>
            <div class="challenge-footer">
                <button class="btn-hint" onclick="showHint('${challenge.id}')">
                    <i class="fas fa-lightbulb"></i> Hint
                </button>
                <div class="flag-input">
                    <input type="text" placeholder="Enter flag" id="flag-${challenge.id}">
                    <button class="btn-submit" onclick="checkFlag('${challenge.id}')">
                        <i class="fas fa-flag"></i> Submit
                    </button>
                </div>
            </div>
        </div>
    `;
    return card;
}
