// CTF API Integration
const API_BASE_URL = 'https://api.tracers-ctf.com'; // You'll need to replace this with your actual API endpoint

class CTFApi {
    static async login(username, password) {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        return response.json();
    }

    static async register(username, email, password) {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password }),
        });
        return response.json();
    }

    static async submitFlag(challengeId, flag) {
        const token = localStorage.getItem('ctf_token');
        const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ flag }),
        });
        return response.json();
    }

    static async getLeaderboard() {
        const response = await fetch(`${API_BASE_URL}/leaderboard`);
        return response.json();
    }

    static async getUserProgress() {
        const token = localStorage.getItem('ctf_token');
        const response = await fetch(`${API_BASE_URL}/user/progress`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        return response.json();
    }

    static async getChallenge(challengeId) {
        const token = localStorage.getItem('ctf_token');
        const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });
        return response.json();
    }
}
