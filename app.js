// Global variables
let currentUser = null;
let userPoints = 0;
let videoMarkers = new Map();

// Initialize all features when the document is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeTooltips();
    addScrollAnimations();
    initializeCTFChallenges();
    initializeVideoPlayer();
    initializeForumFeatures();
    initializeSecurityTools();
});

// CTF Challenges
function initializeCTFChallenges() {
    const challenges = [
        {
            id: 1,
            title: "Basic Encryption",
            difficulty: "Easy",
            points: 100,
            description: "Decode this simple Caesar cipher message",
            content: "Uryyb, guvf vf lbhe svefg CTF punyyratr!"
        },
        // Add more challenges here
    ];

    const challengesContainer = document.querySelector('.challenges-container');
    challenges.forEach(challenge => {
        const challengeElement = createChallengeElement(challenge);
        challengesContainer.appendChild(challengeElement);
    });
}

function createChallengeElement(challenge) {
    const div = document.createElement('div');
    div.className = 'challenge-card card';
    div.innerHTML = `
        <div class="card-body">
            <h3>${challenge.title}</h3>
            <span class="badge bg-primary">${challenge.difficulty}</span>
            <span class="badge bg-success">${challenge.points} pts</span>
            <p>${challenge.description}</p>
            <input type="text" class="form-control mb-2" placeholder="Enter your answer">
            <button class="btn btn-primary" onclick="submitChallenge(${challenge.id})">Submit</button>
        </div>
    `;
    return div;
}

function submitChallenge(challengeId) {
    // Add challenge submission logic here
    console.log('Challenge submitted:', challengeId);
}

// Video Player
function initializeVideoPlayer() {
    const videos = [
        {
            id: 1,
            title: "Introduction to Cybersecurity",
            url: "path_to_video.mp4",
            markers: []
        }
        // Add more videos here
    ];

    const videoContainer = document.getElementById('video-container');
    const videoList = document.querySelector('.video-list');

    videos.forEach(video => {
        const videoElement = createVideoElement(video);
        videoList.appendChild(videoElement);
    });
}

function createVideoElement(video) {
    const div = document.createElement('div');
    div.className = 'video-item';
    div.innerHTML = `
        <h4>${video.title}</h4>
        <button class="btn btn-sm btn-primary" onclick="playVideo(${video.id})">Play</button>
    `;
    return div;
}

function addVideoMarker(videoId, timestamp, note) {
    if (!videoMarkers.has(videoId)) {
        videoMarkers.set(videoId, []);
    }
    videoMarkers.get(videoId).push({ timestamp, note });
    updateMarkerDisplay(videoId);
}

// Forum Features
function initializeForumFeatures() {
    const postForm = document.querySelector('.new-post-form');
    postForm.addEventListener('submit', (e) => {
        e.preventDefault();
        submitForumPost();
    });
}

function submitForumPost() {
    const textarea = document.querySelector('.new-post-form textarea');
    const content = textarea.value.trim();
    
    if (content) {
        const post = {
            content,
            author: currentUser || 'Anonymous',
            timestamp: new Date().toISOString()
        };
        
        addPostToForum(post);
        textarea.value = '';
    }
}

function addPostToForum(post) {
    const postsSection = document.querySelector('.posts-section');
    const postElement = document.createElement('div');
    postElement.className = 'forum-post card mb-3';
    postElement.innerHTML = `
        <div class="card-body">
            <p class="card-text">${post.content}</p>
            <small class="text-muted">Posted by ${post.author} at ${new Date(post.timestamp).toLocaleString()}</small>
        </div>
    `;
    postsSection.appendChild(postElement);
}

// Security Tools
function initializeSecurityTools() {
    const emailChecker = document.querySelector('.tool-card button');
    emailChecker.addEventListener('click', checkEmailSecurity);
}

function checkEmailSecurity() {
    const emailInput = document.querySelector('.tool-card input[type="email"]');
    const email = emailInput.value.trim();
    
    if (email) {
        // Add email security check logic here
        // This is a simple example - you would want more sophisticated checks in production
        const securityScore = calculateEmailSecurityScore(email);
        displaySecurityResult(securityScore);
    }
}

function calculateEmailSecurityScore(email) {
    let score = 0;
    // Add various security checks
    if (email.includes('@') && email.includes('.')) score += 20;
    if (email.length > 10) score += 20;
    if (/[A-Z]/.test(email)) score += 20;
    if (/[0-9]/.test(email)) score += 20;
    if (/[!@#$%^&*]/.test(email)) score += 20;
    return score;
}

function displaySecurityResult(score) {
    alert(`Email Security Score: ${score}/100`);
}

// Add smooth scroll animations
function addScrollAnimations() {
    const elements = document.querySelectorAll('.feature-card, .path-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, {
        threshold: 0.1
    });

    elements.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        element.style.transition = 'all 0.5s ease-out';
        observer.observe(element);
    });
}

// Initialize tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// User Progress Tracking
function updateUserProgress(points) {
    userPoints += points;
    // Add logic to update UI and store progress
    console.log('User points:', userPoints);
}

// Remove dashboard initialization and functions
const dashboardElements = document.querySelectorAll('.dashboard-section, .dashboard-card, .dashboard-stats, .dashboard-progress, .dashboard-activity, .activity-feed, .activity-item');
dashboardElements.forEach(element => {
    if (element) {
        element.remove();
    }
});
