class Leaderboard {
    constructor() {
        this.db = firebase.firestore();
        this.currentFilter = 'all';
        this.currentCategory = 'all';
        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.loadLeaderboard();
    }

    setupEventListeners() {
        // Time filter buttons
        document.querySelectorAll('.btn-group .btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelector('.btn-group .btn.active').classList.remove('active');
                e.target.classList.add('active');
                this.currentFilter = e.target.dataset.filter;
                this.loadLeaderboard();
            });
        });

        // Category filter
        document.getElementById('category-filter').addEventListener('change', (e) => {
            this.currentCategory = e.target.value;
            this.loadLeaderboard();
        });
    }

    async loadLeaderboard() {
        try {
            let query = this.db.collection('users')
                .orderBy('points', 'desc')
                .limit(100);

            // Apply time filter
            if (this.currentFilter !== 'all') {
                const date = new Date();
                if (this.currentFilter === 'month') {
                    date.setMonth(date.getMonth() - 1);
                } else if (this.currentFilter === 'week') {
                    date.setDate(date.getDate() - 7);
                }
                query = query.where('lastActive', '>=', date);
            }

            const snapshot = await query.get();
            const users = snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));

            // Filter by category if needed
            if (this.currentCategory !== 'all') {
                users.sort((a, b) => {
                    const aCount = this.getCategoryChallengesCount(a, this.currentCategory);
                    const bCount = this.getCategoryChallengesCount(b, this.currentCategory);
                    return bCount - aCount;
                });
            }

            this.updateTopPlayers(users.slice(0, 3));
            this.updateLeaderboardTable(users);

        } catch (error) {
            console.error('Error loading leaderboard:', error);
        }
    }

    getCategoryChallengesCount(user, category) {
        return (user.completedChallenges || [])
            .filter(challenge => challenge.startsWith(category + '_'))
            .length;
    }

    updateTopPlayers(topUsers) {
        const positions = ['first', 'second', 'third'];
        topUsers.forEach((user, index) => {
            const position = positions[index];
            document.getElementById(`${position}-place-name`).textContent = user.username;
            document.getElementById(`${position}-place-points`).textContent = `${user.points} pts`;
            document.getElementById(`${position}-place-solved`).textContent = 
                user.completedChallenges ? user.completedChallenges.length : 0;
        });
    }

    updateLeaderboardTable(users) {
        const tbody = document.getElementById('leaderboard-table');
        tbody.innerHTML = '';

        users.forEach((user, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${index + 1}</td>
                <td>
                    <div class="d-flex align-items-center">
                        <i class="fas fa-user-circle me-2"></i>
                        ${user.username}
                        ${this.getSpecialBadges(user)}
                    </div>
                </td>
                <td>${user.points}</td>
                <td>${user.completedChallenges ? user.completedChallenges.length : 0}</td>
                <td>${user.achievements ? user.achievements.length : 0}</td>
                <td>${this.formatLastActive(user.lastActive)}</td>
            `;
            tbody.appendChild(row);
        });
    }

    getSpecialBadges(user) {
        const badges = [];
        
        if (user.achievements && user.achievements.includes('speed_demon')) {
            badges.push('<i class="fas fa-bolt text-warning" title="Speed Demon"></i>');
        }
        if (user.achievements && user.achievements.includes('point_hunter')) {
            badges.push('<i class="fas fa-star text-warning" title="Point Hunter"></i>');
        }
        
        return badges.length ? `<span class="ms-2">${badges.join(' ')}</span>` : '';
    }

    formatLastActive(timestamp) {
        if (!timestamp) return 'Never';
        
        const date = timestamp.toDate();
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
        if (diff < 604800000) return `${Math.floor(diff/86400000)}d ago`;
        
        return date.toLocaleDateString();
    }
}

// Initialize Firebase listeners for leaderboard
function initializeLeaderboard() {
    const timeFilter = document.getElementById('timeFilter');
    if (timeFilter) {
        timeFilter.addEventListener('change', updateLeaderboard);
    }
    updateLeaderboard();
}

// Update leaderboard based on selected time filter
async function updateLeaderboard() {
    const timeFilter = document.getElementById('timeFilter');
    const selectedTime = timeFilter ? timeFilter.value : 'all';
    
    const users = await getTopUsers(selectedTime);
    displayLeaderboard(users);
}

// Get top users from Firebase
async function getTopUsers(timeFilter) {
    const db = firebase.firestore();
    let query = db.collection('users').orderBy('points', 'desc').limit(10);
    
    if (timeFilter === 'month') {
        const monthAgo = new Date();
        monthAgo.setMonth(monthAgo.getMonth() - 1);
        query = query.where('lastActive', '>=', monthAgo);
    } else if (timeFilter === 'week') {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        query = query.where('lastActive', '>=', weekAgo);
    }
    
    const snapshot = await query.get();
    return snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
    }));
}

// Display users in the leaderboard
function displayLeaderboard(users) {
    const leaderboardList = document.getElementById('leaderboardList');
    if (!leaderboardList) return;
    
    leaderboardList.innerHTML = '';
    
    users.forEach((user, index) => {
        const rank = index + 1;
        const item = document.createElement('div');
        item.className = 'leaderboard-item';
        item.setAttribute('data-rank', rank);
        
        // Get appropriate badge for rank
        const badge = getBadgeForRank(rank);
        
        item.innerHTML = `
            <div class="leaderboard-rank">#${rank}</div>
            <img src="${user.photoURL || 'default-avatar.png'}" alt="Avatar" class="leaderboard-avatar">
            <div class="leaderboard-info">
                <div class="leaderboard-name">${user.username || 'Anonymous'}</div>
                <div class="leaderboard-points">
                    ${user.points} points
                    <span class="leaderboard-badge">${badge}</span>
                </div>
            </div>
        `;
        
        leaderboardList.appendChild(item);
    });
}

// Get appropriate badge emoji based on rank
function getBadgeForRank(rank) {
    switch(rank) {
        case 1: return '👑';  // Crown for 1st place
        case 2: return '🥈';  // Silver medal for 2nd
        case 3: return '🥉';  // Bronze medal for 3rd
        case 4:
        case 5: return '⭐';  // Star for 4th and 5th
        default: return '🏴‍☠️';  // Pirate flag for others
    }
}

// Update user's position in leaderboard when they complete a challenge
async function updateUserLeaderboardPosition(userId, points) {
    const db = firebase.firestore();
    const userRef = db.collection('users').doc(userId);
    
    await userRef.update({
        points: firebase.firestore.FieldValue.increment(points),
        lastActive: firebase.firestore.FieldValue.serverTimestamp()
    });
    
    // Refresh the leaderboard
    updateLeaderboard();
}

// Initialize leaderboard when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new Leaderboard();
    initializeLeaderboard();
});
