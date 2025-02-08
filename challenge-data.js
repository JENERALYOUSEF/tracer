// This is just for reference - you'll add these to Firebase
const challengeData = {
    web: {
        easy: [
            {
                id: 'web_e1',
                title: 'Inspector Gadget',
                description: "Something's hidden in the page source. Can you find it?",
                category: 'web',
                difficulty: 'easy',
                points: 100,
                flag: 'flag{source_master}',
                challengeUrl: '/challenges/web/inspector-gadget/',
                hints: [
                    'Right-click and View Page Source',
                    'Look for HTML comments'
                ]
            },
            {
                id: 'web_e2',
                title: 'Cookie Monster',
                description: "There's a secret cookie on this page.",
                category: 'web',
                difficulty: 'easy',
                points: 100,
                flag: 'flag{cookie_hunter}',
                challengeUrl: '/challenges/web/cookie-monster/',
                hints: [
                    'Check browser developer tools',
                    'Look in the Storage/Cookies tab'
                ]
            }
        ],
        medium: [
            {
                id: 'web_m1',
                title: 'SQL Injection 101',
                description: "Login to the admin account without knowing the password.",
                category: 'web',
                difficulty: 'medium',
                points: 200,
                flag: 'flag{sql_master}',
                challengeUrl: '/challenges/web/sql-injection/',
                hints: [
                    'Try using single quotes in the input',
                    "What happens if you add OR '1'='1'?"
                ]
            }
        ]
    },
    forensics: {
        easy: [
            {
                id: 'forensics_e1',
                title: 'Hidden Message',
                description: "This text file contains a secret message in binary.",
                category: 'forensics',
                difficulty: 'easy',
                points: 100,
                flag: 'flag{forensics_pro}',
                challengeUrl: '/challenges/forensics/hidden-message/secret.txt',
                hints: [
                    'The message is encoded in binary',
                    'Convert binary to ASCII'
                ]
            }
        ]
    }
};
