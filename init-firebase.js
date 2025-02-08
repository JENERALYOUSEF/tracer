// Run this script to initialize your Firebase database with challenges
async function initializeDatabase() {
    const db = firebase.firestore();
    
    // Initialize challenges collection
    const challenges = [
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
        },
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
    ];

    // Initialize achievements collection
    const achievements = [
        {
            id: 'first_blood',
            title: 'First Blood',
            description: 'Solve your first challenge',
            icon: 'fa-trophy',
            points: 50
        },
        {
            id: 'web_master',
            title: 'Web Master',
            description: 'Solve 5 web challenges',
            icon: 'fa-globe',
            points: 100
        },
        {
            id: 'forensics_expert',
            title: 'Digital Detective',
            description: 'Solve 5 forensics challenges',
            icon: 'fa-search',
            points: 100
        },
        {
            id: 'crypto_king',
            title: 'Crypto King',
            description: 'Solve 5 crypto challenges',
            icon: 'fa-key',
            points: 100
        },
        {
            id: 'point_hunter',
            title: 'Point Hunter',
            description: 'Earn 1000 points',
            icon: 'fa-star',
            points: 200
        },
        {
            id: 'speed_demon',
            title: 'Speed Demon',
            description: 'Solve 3 challenges in one day',
            icon: 'fa-bolt',
            points: 150
        }
    ];

    // Add each challenge to Firestore
    for (const challenge of challenges) {
        await db.collection('challenges').doc(challenge.id).set(challenge);
        console.log(`Added challenge: ${challenge.title}`);
    }

    // Add each achievement to Firestore
    for (const achievement of achievements) {
        await db.collection('achievements').doc(achievement.id).set(achievement);
        console.log(`Added achievement: ${achievement.title}`);
    }

    // Create indexes for queries
    try {
        await db.collection('activity')
            .orderBy('timestamp', 'desc')
            .limit(1)
            .get();

        await db.collection('users')
            .orderBy('points', 'desc')
            .limit(10)
            .get();

        console.log('Indexes created successfully');
    } catch (error) {
        console.error('Error creating indexes:', error);
        console.log('Please create the following indexes in your Firebase Console:');
        console.log('Collection: activity, Fields: userId ASC, timestamp DESC');
        console.log('Collection: users, Fields: points DESC');
    }

    console.log('Database initialization complete!');
}

// Run the initialization
initializeDatabase().catch(console.error);
